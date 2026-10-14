// Package identity obtains short-lived workload certificates from LabCA,
// keeps the private keys in memory, and renews them before they expire.
package identity

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	mrand "math/rand/v2"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Cameloo1/labca/mtls-demo/internal/labcaapi"
	"github.com/Cameloo1/labca/mtls-demo/internal/spiffe"
)

// Clock abstracts time so tests can drive renewal deterministically.
type Clock interface {
	Now() time.Time
	After(d time.Duration) <-chan time.Time
}

type realClock struct{}

func (realClock) Now() time.Time                         { return time.Now() }
func (realClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// RealClock returns a Clock backed by the system clock.
func RealClock() Clock { return realClock{} }

// Info is a snapshot of the current identity.
type Info struct {
	SPIFFEID, SerialHex string
	NotAfter            time.Time
	Renewals            int
}

// Config configures a Source.
type Config struct {
	LabCA           *labcaapi.Client
	TokenFile       string         // re-read on every sign and revoke call
	TrustBundleFile string         // PEM roots; reloaded when content changes
	TrustRefresh    time.Duration  // default 30s
	Clock           Clock          // default RealClock()
	Rand            func() float64 // default math/rand/v2 Float64; used for jitter
	BackoffInitial  time.Duration  // default 1s
	BackoffMax      time.Duration  // default 60s
	Logger          *slog.Logger
}

// Issued is one issued certificate with its key.
type Issued struct {
	Cert     tls.Certificate
	Leaf     *x509.Certificate
	Issuer   *x509.Certificate
	SPIFFEID string
}

// Source holds the current workload identity and trust bundle.
type Source struct {
	cfg      Config
	cur      atomic.Pointer[Issued]
	pool     atomic.Pointer[x509.CertPool]
	renewals atomic.Int64

	trustMu  sync.Mutex
	trustRaw []byte
}

// New validates cfg, fills defaults and returns a Source.
func New(cfg Config) (*Source, error) {
	if cfg.LabCA == nil {
		return nil, errors.New("identity: LabCA client is required")
	}
	if cfg.TokenFile == "" || cfg.TrustBundleFile == "" {
		return nil, errors.New("identity: TokenFile and TrustBundleFile are required")
	}
	if cfg.TrustRefresh <= 0 {
		cfg.TrustRefresh = 30 * time.Second
	}
	if cfg.Clock == nil {
		cfg.Clock = RealClock()
	}
	if cfg.Rand == nil {
		cfg.Rand = mrand.Float64
	}
	if cfg.BackoffInitial <= 0 {
		cfg.BackoffInitial = time.Second
	}
	if cfg.BackoffMax <= 0 {
		cfg.BackoffMax = 60 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Source{cfg: cfg}, nil
}

// NextRenewal returns notBefore + lifetime*(0.4 + 0.2*r) for r in [0,1).
func NextRenewal(notBefore, notAfter time.Time, r float64) time.Time {
	life := notAfter.Sub(notBefore)
	return notBefore.Add(time.Duration(float64(life) * (0.4 + 0.2*r)))
}

// Backoff returns initial*2^attempt capped at max.
func Backoff(attempt int, initial, max time.Duration) time.Duration {
	d := initial
	for i := 0; i < attempt; i++ {
		if d >= max {
			break
		}
		d *= 2
	}
	if d > max {
		d = max
	}
	return d
}

// Token reads the ServiceAccount token file now.
func (s *Source) Token() (string, error) {
	b, err := os.ReadFile(s.cfg.TokenFile)
	if err != nil {
		return "", fmt.Errorf("identity: read token file: %w", err)
	}
	t := strings.TrimSpace(string(b))
	if t == "" {
		return "", errors.New("identity: token file is empty")
	}
	return t, nil
}

func (s *Source) loadTrust() (bool, error) {
	raw, err := os.ReadFile(s.cfg.TrustBundleFile)
	if err != nil {
		return false, fmt.Errorf("identity: read trust bundle: %w", err)
	}
	s.trustMu.Lock()
	defer s.trustMu.Unlock()
	if s.trustRaw != nil && bytes.Equal(raw, s.trustRaw) {
		return false, nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		return false, errors.New("identity: trust bundle has no certificates")
	}
	s.pool.Store(pool)
	s.trustRaw = raw
	return true, nil
}

// Roots returns the current trust bundle pool (empty before Start).
func (s *Source) Roots() *x509.CertPool {
	if p := s.pool.Load(); p != nil {
		return p
	}
	return x509.NewCertPool()
}

func parseCerts(pemData string) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := []byte(pemData)
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("unexpected PEM block %q", blk.Type)
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("trailing data after PEM")
	}
	return out, nil
}

// Issue performs one issuance with a fresh key. It does not install the result.
func (s *Source) Issue(ctx context.Context) (*Issued, error) {
	pool := s.pool.Load()
	if pool == nil {
		return nil, errors.New("identity: trust bundle not loaded")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("identity: generate key: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "mtls-demo"},
	}, key)
	if err != nil {
		return nil, fmt.Errorf("identity: create CSR: %w", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	token, err := s.Token()
	if err != nil {
		return nil, err
	}
	resp, err := s.cfg.LabCA.Sign(ctx, token, csrPEM)
	if err != nil {
		return nil, err
	}
	leaves, err := parseCerts(resp.CertificatePEM)
	if err != nil || len(leaves) != 1 {
		return nil, fmt.Errorf("identity: certificate_pem must hold exactly one certificate (err=%v, n=%d)", err, len(leaves))
	}
	leaf := leaves[0]
	chain, err := parseCerts(resp.ChainPEM)
	if err != nil {
		return nil, fmt.Errorf("identity: parse chain_pem: %w", err)
	}
	if len(chain) > 0 && bytes.Equal(chain[0].Raw, leaf.Raw) {
		chain = chain[1:]
	}
	if !key.PublicKey.Equal(leaf.PublicKey) {
		return nil, errors.New("identity: issued certificate does not match our key")
	}
	id, err := spiffe.FromCertificate(leaf)
	if err != nil {
		return nil, err
	}
	if id != resp.SPIFFEID {
		return nil, fmt.Errorf("identity: certificate SPIFFE ID %q differs from response %q", id, resp.SPIFFEID)
	}
	inter := x509.NewCertPool()
	for _, c := range chain {
		inter.AddCert(c)
	}
	var verified [][]*x509.Certificate
	for _, usage := range []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth} {
		chains, verr := leaf.Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter, CurrentTime: s.cfg.Clock.Now(), KeyUsages: []x509.ExtKeyUsage{usage}})
		if verr != nil {
			return nil, fmt.Errorf("identity: issued certificate does not verify: %w", verr)
		}
		verified = chains
	}
	vc := verified[0]
	der := [][]byte{leaf.Raw}
	for _, c := range vc[1 : len(vc)-1] {
		der = append(der, c.Raw)
	}
	var issuer *x509.Certificate
	if len(vc) > 1 {
		issuer = vc[1]
	}
	return &Issued{
		Cert:     tls.Certificate{Certificate: der, PrivateKey: key, Leaf: leaf},
		Leaf:     leaf,
		Issuer:   issuer,
		SPIFFEID: id,
	}, nil
}

func (s *Source) wait(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.cfg.Clock.After(d):
		return nil
	}
}

func (s *Source) retryDelay(err error, attempt int) time.Duration {
	d := Backoff(attempt, s.cfg.BackoffInitial, s.cfg.BackoffMax)
	var ae *labcaapi.APIError
	if errors.As(err, &ae) && ae.RetryAfter > d {
		d = ae.RetryAfter
	}
	if d > s.cfg.BackoffMax {
		d = s.cfg.BackoffMax
	}
	return d
}

// issueWithRetry retries until success or ctx is done.
func (s *Source) issueWithRetry(ctx context.Context) (*Issued, error) {
	for attempt := 0; ; attempt++ {
		iss, err := s.Issue(ctx)
		if err == nil {
			return iss, nil
		}
		s.cfg.Logger.Warn("issuance failed", "attempt", attempt, "error", err.Error())
		if werr := s.wait(ctx, s.retryDelay(err, attempt)); werr != nil {
			return nil, werr
		}
	}
}

// Start loads the trust bundle, obtains the first certificate and then runs
// the renewal and trust reload loops until ctx is done.
func (s *Source) Start(ctx context.Context) error {
	if _, err := s.loadTrust(); err != nil {
		return err
	}
	iss, err := s.issueWithRetry(ctx)
	if err != nil {
		return err
	}
	s.cur.Store(iss)
	s.cfg.Logger.Info("identity issued", "spiffe_id", iss.SPIFFEID, "serial_hex", iss.Leaf.SerialNumber.Text(16),
		"not_after", iss.Leaf.NotAfter.UTC().Format(time.RFC3339))
	go s.renewLoop(ctx)
	go s.trustLoop(ctx)
	return nil
}

func (s *Source) renewLoop(ctx context.Context) {
	for {
		cur := s.cur.Load()
		at := NextRenewal(cur.Leaf.NotBefore, cur.Leaf.NotAfter, s.cfg.Rand())
		if err := s.wait(ctx, at.Sub(s.cfg.Clock.Now())); err != nil {
			return
		}
		iss, err := s.issueWithRetry(ctx)
		if err != nil {
			return
		}
		s.cur.Store(iss)
		s.renewals.Add(1)
		s.cfg.Logger.Info("identity renewed", "spiffe_id", iss.SPIFFEID, "serial_hex", iss.Leaf.SerialNumber.Text(16),
			"not_after", iss.Leaf.NotAfter.UTC().Format(time.RFC3339))
	}
}

func (s *Source) trustLoop(ctx context.Context) {
	for {
		if err := s.wait(ctx, s.cfg.TrustRefresh); err != nil {
			return
		}
		changed, err := s.loadTrust()
		if err != nil {
			s.cfg.Logger.Warn("trust bundle reload failed, keeping previous", "error", err.Error())
			continue
		}
		if changed {
			s.cfg.Logger.Info("trust bundle reloaded")
		}
	}
}

// GetCertificate serves the current certificate to TLS servers.
func (s *Source) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return s.tlsCert()
}

// GetClientCertificate serves the current certificate to TLS clients.
func (s *Source) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return s.tlsCert()
}

func (s *Source) tlsCert() (*tls.Certificate, error) {
	cur := s.cur.Load()
	if cur == nil {
		return nil, errors.New("identity: no certificate issued yet")
	}
	return &cur.Cert, nil
}

// Current returns a snapshot of the current identity.
func (s *Source) Current() Info {
	cur := s.cur.Load()
	if cur == nil {
		return Info{Renewals: int(s.renewals.Load())}
	}
	return Info{
		SPIFFEID:  cur.SPIFFEID,
		SerialHex: cur.Leaf.SerialNumber.Text(16),
		NotAfter:  cur.Leaf.NotAfter,
		Renewals:  int(s.renewals.Load()),
	}
}

// Ready reports whether an unexpired certificate is installed.
func (s *Source) Ready() bool {
	cur := s.cur.Load()
	return cur != nil && s.cfg.Clock.Now().Before(cur.Leaf.NotAfter)
}

// IssuingCA returns the issuer of the current certificate, or nil.
func (s *Source) IssuingCA() *x509.Certificate {
	if cur := s.cur.Load(); cur != nil {
		return cur.Issuer
	}
	return nil
}
