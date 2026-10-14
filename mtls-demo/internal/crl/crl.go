// Package crl fetches and verifies the issuing CA's CRL and answers
// revocation queries. It fails closed: no valid CRL means "revoked".
package crl

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/Cameloo1/labca/mtls-demo/internal/identity"
)

// ErrNoValidCRL means no CRL has been loaded successfully.
var ErrNoValidCRL = errors.New("crl: no valid CRL loaded")

// ErrStaleCRL means the loaded CRL is past its nextUpdate.
var ErrStaleCRL = errors.New("crl: CRL is past nextUpdate")

// ErrIssuerMismatch means the certificate was not issued by the CA whose CRL is loaded.
var ErrIssuerMismatch = errors.New("crl: certificate issuer is not the CRL issuer")

const maxCRLBytes = 5 << 20

// Status describes the loaded CRL.
type Status struct {
	Number                            int64
	ThisUpdate, NextUpdate, FetchedAt time.Time
	RevokedCount                      int
	Valid                             bool
}

// Config configures a Fetcher.
type Config struct {
	URL        string
	Refresh    time.Duration            // default 30s
	HTTP       *http.Client             // timeout 10s by default
	Issuer     func() *x509.Certificate // issuing CA to verify against
	Clock      identity.Clock
	AllowStale bool // TEST ONLY: never wired to env or flags
	Logger     *slog.Logger
}

type loaded struct {
	number     int64
	thisUpdate time.Time
	nextUpdate time.Time
	fetchedAt  time.Time
	revoked    map[string]struct{}
	issuerRaw  []byte
}

// Fetcher holds the current CRL.
type Fetcher struct {
	cfg Config
	cur atomic.Pointer[loaded]
}

// New returns a Fetcher with defaults filled in.
func New(cfg Config) *Fetcher {
	if cfg.Refresh <= 0 {
		cfg.Refresh = 30 * time.Second
	}
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.Clock == nil {
		cfg.Clock = identity.RealClock()
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Fetcher{cfg: cfg}
}

// Start fetches now and then every Refresh until ctx is done. Until the first
// valid CRL arrives it retries sooner than Refresh.
func (f *Fetcher) Start(ctx context.Context) {
	for {
		if err := f.Refresh(ctx); err != nil {
			f.cfg.Logger.Warn("crl refresh failed", "error", err.Error())
		}
		wait := f.cfg.Refresh
		if f.cur.Load() == nil && wait > 500*time.Millisecond {
			wait = 500 * time.Millisecond
		}
		select {
		case <-ctx.Done():
			return
		case <-f.cfg.Clock.After(wait):
		}
	}
}

// Refresh downloads and verifies the CRL, then swaps it in.
func (f *Fetcher) Refresh(ctx context.Context) error {
	issuer := f.cfg.Issuer()
	if issuer == nil {
		return errors.New("crl: issuing CA not known yet")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.cfg.URL, nil)
	if err != nil {
		return err
	}
	resp, err := f.cfg.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("crl: fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("crl: fetch: HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxCRLBytes+1))
	if err != nil {
		return fmt.Errorf("crl: read body: %w", err)
	}
	if len(data) > maxCRLBytes {
		return errors.New("crl: body exceeds 5 MiB")
	}
	list, err := x509.ParseRevocationList(data)
	if err != nil {
		return fmt.Errorf("crl: parse: %w", err)
	}
	if err := list.CheckSignatureFrom(issuer); err != nil {
		return fmt.Errorf("crl: signature: %w", err)
	}
	if !bytes.Equal(list.RawIssuer, issuer.RawSubject) {
		return errors.New("crl: issuer name does not match the issuing CA")
	}
	if list.Number == nil || !list.Number.IsInt64() {
		return errors.New("crl: missing or oversized CRL number")
	}
	if list.NextUpdate.IsZero() {
		return errors.New("crl: missing nextUpdate")
	}
	n := list.Number.Int64()
	if prev := f.cur.Load(); prev != nil && n < prev.number {
		return fmt.Errorf("crl: number rolled back from %d to %d", prev.number, n)
	}
	set := make(map[string]struct{}, len(list.RevokedCertificateEntries))
	for _, e := range list.RevokedCertificateEntries {
		set[e.SerialNumber.String()] = struct{}{}
	}
	f.cur.Store(&loaded{
		number:     n,
		thisUpdate: list.ThisUpdate,
		nextUpdate: list.NextUpdate,
		fetchedAt:  f.cfg.Clock.Now(),
		revoked:    set,
		issuerRaw:  append([]byte(nil), issuer.Raw...),
	})
	return nil
}

// IsRevoked fails closed: it returns true with an error when it cannot answer.
func (f *Fetcher) IsRevoked(serial *big.Int) (bool, error) {
	cur := f.cur.Load()
	if cur == nil {
		return true, ErrNoValidCRL
	}
	if !f.cfg.AllowStale && f.cfg.Clock.Now().After(cur.nextUpdate) {
		return true, ErrStaleCRL
	}
	_, listed := cur.revoked[serial.String()]
	return listed, nil
}

// Fresh reports whether a CRL is loaded and not past nextUpdate.
func (f *Fetcher) Fresh() bool {
	cur := f.cur.Load()
	if cur == nil {
		return false
	}
	return f.cfg.AllowStale || !f.cfg.Clock.Now().After(cur.nextUpdate)
}

// Status returns a snapshot of the loaded CRL.
func (f *Fetcher) Status() Status {
	cur := f.cur.Load()
	if cur == nil {
		return Status{}
	}
	return Status{
		Number:       cur.number,
		ThisUpdate:   cur.thisUpdate,
		NextUpdate:   cur.nextUpdate,
		FetchedAt:    cur.fetchedAt,
		RevokedCount: len(cur.revoked),
		Valid:        f.Fresh(),
	}
}

// Check reports whether leaf is revoked. It fails closed: any error comes
// with revoked set to true. The leaf must have been issued by issuer, and
// issuer must be the certificate the loaded CRL was verified against, because
// serial numbers are only unique per issuer.
func (f *Fetcher) Check(leaf *x509.Certificate, issuer *x509.Certificate) (revoked bool, err error) {
	cur := f.cur.Load()
	if cur == nil {
		return true, ErrNoValidCRL
	}
	if !f.cfg.AllowStale && f.cfg.Clock.Now().After(cur.nextUpdate) {
		return true, ErrStaleCRL
	}
	if leaf == nil || issuer == nil || !bytes.Equal(issuer.Raw, cur.issuerRaw) {
		return true, ErrIssuerMismatch
	}
	if err := leaf.CheckSignatureFrom(issuer); err != nil {
		return true, ErrIssuerMismatch
	}
	_, listed := cur.revoked[leaf.SerialNumber.String()]
	return listed, nil
}
