// Package verifier implements the verifier subcommand: it attacks the demo
// server with identities that must fail and one that must pass, then
// publishes the results to a ConfigMap.
package verifier

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/Cameloo1/labca/mtls-demo/internal/identity"
	"github.com/Cameloo1/labca/mtls-demo/internal/labcaapi"
	"github.com/Cameloo1/labca/mtls-demo/internal/spiffe"
)

// Scenario is one verifier check.
type Scenario struct {
	Name       string `json:"name"`
	Passed     bool   `json:"passed"`
	Expected   string `json:"expected"`
	Observed   string `json:"observed"`
	DurationMS int64  `json:"duration_ms"`
}

// Results is the document stored in the ConfigMap.
type Results struct {
	RunAt     string     `json:"run_at"`
	AllPassed bool       `json:"all_passed"`
	Scenarios []Scenario `json:"scenarios"`
}

// DialFunc makes the TCP connection to the server under test.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Config holds the verifier's settings.
type Config struct {
	LabCAURL             string
	TokenFile            string
	TrustBundleFile      string
	ServerURL            string
	ServerStatusURL      string
	DemoClientID         string
	ExpectedServerID     string
	AuthorizedCallMaxAge time.Duration
	RevokeWaitTimeout    time.Duration
	RevokePollInterval   time.Duration
	KubeAPIURL           string
	KubeTokenFile        string
	KubeCAFile           string
	PodNamespace         string
	StatusConfigMap      string
}

// Verifier runs the scenarios.
type Verifier struct {
	Cfg   Config
	Src   *identity.Source
	LabCA *labcaapi.Client
	Clock identity.Clock
	HTTP  *http.Client // used for the server status URL
	Dial  DialFunc     // nil means a plain TCP dial with a 5s timeout
}

func (v *Verifier) clock() identity.Clock {
	if v.Clock == nil {
		return identity.RealClock()
	}
	return v.Clock
}

func (v *Verifier) httpClient() *http.Client {
	if v.HTTP != nil {
		return v.HTTP
	}
	return &http.Client{Timeout: 10 * time.Second}
}

// Attempt kinds.
const (
	kindUnreachable = "unreachable"
	kindRejected    = "rejected"
	kindResponse    = "response"
	kindError       = "error"
)

type attemptResult struct {
	Kind   string
	Status int
	Detail string
}

func (a attemptResult) String() string {
	switch a.Kind {
	case kindResponse:
		return fmt.Sprintf("response: HTTP %d", a.Status)
	default:
		return a.Kind + ": " + a.Detail
	}
}

// isTLSRejection reports whether err shows that the server rejected us: a
// received TLS alert, or (after a completed handshake) the server closing the
// connection. Local verification failures and timeouts are not rejections.
func isTLSRejection(err error, handshakeDone bool) bool {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return false
	}
	var oe *net.OpError
	if errors.As(err, &oe) && oe.Op == "remote error" {
		return true
	}
	return handshakeDone && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE))
}

// isLocalTLSError reports whether err came from our own side of the handshake.
func isLocalTLSError(err error) bool {
	var cve *tls.CertificateVerificationError
	return errors.As(err, &cve) || strings.Contains(err.Error(), "tls:")
}

// attempt dials the server, handshakes presenting cert (nil means none),
// sends GET /v1/ping and classifies the outcome.
func (v *Verifier) attempt(ctx context.Context, cert *tls.Certificate) attemptResult {
	u, err := url.Parse(v.Cfg.ServerURL)
	if err != nil {
		return attemptResult{Kind: kindError, Detail: "bad SERVER_URL: " + err.Error()}
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	dial := v.Dial
	if dial == nil {
		d := &net.Dialer{Timeout: 5 * time.Second}
		dial = d.DialContext
	}
	dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := dial(dctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return attemptResult{Kind: kindUnreachable, Detail: err.Error()}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	tc := tls.Client(conn, &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    v.Src.Roots(),
		ServerName: host,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			if cert == nil {
				return &tls.Certificate{}, nil
			}
			return cert, nil
		},
	})
	hctx, hcancel := context.WithTimeout(ctx, 10*time.Second)
	defer hcancel()
	if err := tc.HandshakeContext(hctx); err != nil {
		if isTLSRejection(err, false) {
			return attemptResult{Kind: kindRejected, Detail: "handshake: " + err.Error()}
		}
		if isLocalTLSError(err) {
			return attemptResult{Kind: kindError, Detail: "local tls error: " + err.Error()}
		}
		return attemptResult{Kind: kindError, Detail: "handshake: " + err.Error()}
	}
	cs := tc.ConnectionState()
	if len(cs.PeerCertificates) == 0 {
		return attemptResult{Kind: kindError, Detail: "server presented no certificate"}
	}
	sid, err := spiffe.FromCertificate(cs.PeerCertificates[0])
	if err != nil || sid != v.Cfg.ExpectedServerID {
		return attemptResult{Kind: kindError, Detail: fmt.Sprintf("unexpected server identity %q", sid)}
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+net.JoinHostPort(host, port)+"/v1/ping", nil)
	req.Close = true
	if err := req.Write(tc); err != nil {
		if isTLSRejection(err, true) {
			return attemptResult{Kind: kindRejected, Detail: "write: " + err.Error()}
		}
		return attemptResult{Kind: kindError, Detail: "write: " + err.Error()}
	}
	resp, err := http.ReadResponse(bufio.NewReader(tc), req)
	if err != nil {
		if isTLSRejection(err, true) {
			return attemptResult{Kind: kindRejected, Detail: "after handshake: " + err.Error()}
		}
		return attemptResult{Kind: kindError, Detail: "read: " + err.Error()}
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	return attemptResult{Kind: kindResponse, Status: resp.StatusCode}
}

// forge builds an in-memory self-signed CA and a leaf signed by it that
// claims the given SPIFFE ID. Nothing is written anywhere.
func forge(id string) (*tls.Certificate, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Forged Demo CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(id)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "forged-client"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{u},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: key}, nil
}

type serverStatus struct {
	CRL struct {
		Number int64 `json:"number"`
	} `json:"crl"`
	LastAuthorizedCall *struct {
		ClientID string `json:"client_id"`
		At       string `json:"at"`
	} `json:"last_authorized_call"`
}

func (v *Verifier) fetchStatus(ctx context.Context) (*serverStatus, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.Cfg.ServerStatusURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := v.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status endpoint returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var st serverStatus
	if err := json.Unmarshal(body, &st); err != nil {
		return nil, fmt.Errorf("status endpoint returned invalid JSON: %w", err)
	}
	return &st, nil
}

// runScenario times fn and converts panics into failures.
func (v *Verifier) runScenario(name, expected string, fn func() (bool, string)) (s Scenario) {
	clk := v.clock()
	start := clk.Now()
	s = Scenario{Name: name, Expected: expected}
	defer func() {
		if r := recover(); r != nil {
			s.Passed = false
			s.Observed = fmt.Sprintf("panic: %v", r)
		}
		s.DurationMS = clk.Now().Sub(start).Milliseconds()
	}()
	s.Passed, s.Observed = fn()
	return s
}

// RunAll runs the five scenarios in order and returns the results.
func (v *Verifier) RunAll(ctx context.Context) Results {
	clk := v.clock()
	runAt := clk.Now().UTC()

	// Control: a valid identity must get an HTTP response. Without this a
	// verifier that cannot talk to the server at all would "prove" rejections.
	var control attemptResult
	if own, err := v.Src.GetClientCertificate(nil); err == nil {
		control = v.attempt(ctx, own)
	} else {
		control = attemptResult{Kind: kindError, Detail: "no verifier certificate: " + err.Error()}
	}
	controlOK := control.Kind == kindResponse
	rejectionScenario := func(name, expected string, cert func() (*tls.Certificate, error)) Scenario {
		return v.runScenario(name, expected, func() (bool, string) {
			if !controlOK {
				return false, "control attempt with a valid identity got no response (" + control.String() + ")"
			}
			c, err := cert()
			if err != nil {
				return false, "could not build identity: " + err.Error()
			}
			a := v.attempt(ctx, c)
			return a.Kind == kindRejected, a.String()
		})
	}

	var out []Scenario
	out = append(out, v.runScenario("authorized_client_observed",
		fmt.Sprintf("server saw an authorized call from %s within %s", v.Cfg.DemoClientID, v.Cfg.AuthorizedCallMaxAge),
		func() (bool, string) {
			st, err := v.fetchStatus(ctx)
			if err != nil {
				return false, "status fetch failed: " + err.Error()
			}
			if st.LastAuthorizedCall == nil {
				return false, "no authorized call recorded"
			}
			at, err := time.Parse(time.RFC3339, st.LastAuthorizedCall.At)
			if err != nil {
				return false, "unparseable call time: " + err.Error()
			}
			age := clk.Now().Sub(at)
			obs := fmt.Sprintf("last call by %s at %s (age %s)", st.LastAuthorizedCall.ClientID, st.LastAuthorizedCall.At, age.Round(time.Second))
			return st.LastAuthorizedCall.ClientID == v.Cfg.DemoClientID && age <= v.Cfg.AuthorizedCallMaxAge, obs
		}))

	out = append(out, rejectionScenario("no_client_cert_rejected",
		"handshake or first read fails with a TLS alert when no client certificate is presented",
		func() (*tls.Certificate, error) { return nil, nil }))

	out = append(out, rejectionScenario("forged_identity_rejected",
		"a certificate from an untrusted CA claiming the demo client SPIFFE ID is rejected",
		func() (*tls.Certificate, error) { return forge(v.Cfg.DemoClientID) }))

	out = append(out, v.runScenario("unauthorized_identity_forbidden",
		"a valid certificate for an identity outside the allowlist gets HTTP 403",
		func() (bool, string) {
			own, err := v.Src.GetClientCertificate(nil)
			if err != nil {
				return false, "no verifier certificate: " + err.Error()
			}
			a := v.attempt(ctx, own)
			return a.Kind == kindResponse && a.Status == http.StatusForbidden, a.String()
		}))

	out = append(out, v.runScenario("revoked_identity_rejected",
		"a certificate revoked through the LabCA API is rejected once the server loads the new CRL",
		func() (bool, string) {
			if !controlOK {
				return false, "control attempt with a valid identity got no response (" + control.String() + ")"
			}
			iss, err := v.Src.Issue(ctx)
			if err != nil {
				return false, "issuing second certificate failed: " + err.Error()
			}
			token, err := v.Src.Token()
			if err != nil {
				return false, "token: " + err.Error()
			}
			serial := iss.Leaf.SerialNumber.Text(16)
			rr, err := v.LabCA.Revoke(ctx, token, serial, "keyCompromise")
			if err != nil {
				return false, "revoke failed: " + err.Error()
			}
			deadline := clk.Now().Add(v.Cfg.RevokeWaitTimeout)
			for {
				st, err := v.fetchStatus(ctx)
				if err == nil && st.CRL.Number >= rr.CRLNumber {
					break
				}
				if !clk.Now().Before(deadline) {
					return false, fmt.Sprintf("crl not updated within %s (need number >= %d)", v.Cfg.RevokeWaitTimeout, rr.CRLNumber)
				}
				select {
				case <-ctx.Done():
					return false, "context done while waiting for CRL: " + ctx.Err().Error()
				case <-clk.After(v.Cfg.RevokePollInterval):
				}
			}
			a := v.attempt(ctx, &iss.Cert)
			return a.Kind == kindRejected, fmt.Sprintf("serial %s revoked at CRL %d; %s", serial, rr.CRLNumber, a.String())
		}))

	all := true
	for _, s := range out {
		all = all && s.Passed
	}
	return Results{RunAt: runAt.Format(time.RFC3339), AllPassed: all, Scenarios: out}
}
