package identity_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Cameloo1/labca/mtls-demo/internal/fakelabca"
	"github.com/Cameloo1/labca/mtls-demo/internal/identity"
	"github.com/Cameloo1/labca/mtls-demo/internal/labcaapi"
)

const trustDomain = "labca.test"

type env struct {
	fake  *fakelabca.Server
	dir   string
	token string
	trust string
	cfg   identity.Config
}

func newEnv(t *testing.T) *env {
	t.Helper()
	fake := fakelabca.New(trustDomain)
	t.Cleanup(fake.Close)
	fake.AddToken("tok1", "mtls-demo", "demo-server")
	fake.AddToken("tok2", "mtls-demo", "demo-server")
	dir := t.TempDir()
	e := &env{fake: fake, dir: dir, token: filepath.Join(dir, "token"), trust: filepath.Join(dir, "trust.pem")}
	if err := os.WriteFile(e.token, []byte("tok1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.trust, fake.RootPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	e.cfg = identity.Config{
		LabCA:           &labcaapi.Client{BaseURL: fake.URL},
		TokenFile:       e.token,
		TrustBundleFile: e.trust,
		BackoffInitial:  time.Millisecond,
		BackoffMax:      5 * time.Millisecond,
	}
	return e
}

func (e *env) source(t *testing.T) *identity.Source {
	t.Helper()
	s, err := identity.New(e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestNextRenewalBounds(t *testing.T) {
	nb := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	na := nb.Add(time.Hour)
	if got := identity.NextRenewal(nb, na, 0); got != nb.Add(24*time.Minute) {
		t.Errorf("r=0: %v", got)
	}
	if got := identity.NextRenewal(nb, na, 0.5); got != nb.Add(30*time.Minute) {
		t.Errorf("r=0.5: %v", got)
	}
	got := identity.NextRenewal(nb, na, 0.999999)
	if got.Before(nb.Add(35*time.Minute+59*time.Second)) || !got.Before(nb.Add(36*time.Minute)) {
		t.Errorf("r~1: %v", got.Sub(nb))
	}
}

func TestBackoffCapped(t *testing.T) {
	in, mx := time.Second, 60*time.Second
	want := []time.Duration{1, 2, 4, 8, 16, 32, 60, 60}
	for i, w := range want {
		if got := identity.Backoff(i, in, mx); got != w*time.Second {
			t.Errorf("attempt %d: %v", i, got)
		}
	}
	if got := identity.Backoff(1000, in, mx); got != mx {
		t.Errorf("huge attempt: %v", got)
	}
}

func TestIssueVerifiesChainAndKey(t *testing.T) {
	e := newEnv(t)
	s := e.source(t)
	if _, err := s.Issue(context.Background()); err == nil {
		t.Fatal("Issue before the trust bundle is loaded must fail")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	iss, err := s.Issue(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := iss.SPIFFEID, "spiffe://labca.test/ns/mtls-demo/sa/demo-server"; got != want {
		t.Errorf("spiffe id %q", got)
	}
	if len(iss.Cert.Certificate) != 2 {
		t.Errorf("chain length %d, want 2", len(iss.Cert.Certificate))
	}
	key, ok := iss.Cert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok || !key.PublicKey.Equal(iss.Leaf.PublicKey) {
		t.Error("private key does not match leaf")
	}
	if iss.Issuer == nil || iss.Issuer.Subject.CommonName != "Fake Issuing CA" {
		t.Errorf("issuer %v", iss.Issuer)
	}
	cur := s.Current()
	if cur.SPIFFEID != "spiffe://labca.test/ns/mtls-demo/sa/demo-server" || cur.SerialHex == "" || cur.Renewals != 0 || cur.NotAfter.IsZero() {
		t.Errorf("current %+v", cur)
	}
	if !s.Ready() || s.IssuingCA() == nil {
		t.Error("expected ready with issuing CA")
	}
	c, err := s.GetCertificate(nil)
	if err != nil || len(c.Certificate) != 2 {
		t.Errorf("GetCertificate: %v", err)
	}
	if _, err := s.GetClientCertificate(nil); err != nil {
		t.Errorf("GetClientCertificate: %v", err)
	}
}

func TestIssueRejectsWrongRoots(t *testing.T) {
	e := newEnv(t)
	other := fakelabca.New(trustDomain)
	defer other.Close()
	if err := os.WriteFile(e.trust, other.RootPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	s := e.source(t)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	// Start retries until ctx is done, so it must return an error and never install a cert.
	if err := s.Start(ctx); err == nil {
		t.Fatal("Start must fail when the issued cert does not verify")
	}
	if s.Ready() {
		t.Fatal("must not be ready")
	}
	if _, err := s.Issue(context.Background()); err == nil {
		t.Fatal("Issue must fail with wrong roots")
	}
}

func TestTokenFileReReadEachCall(t *testing.T) {
	e := newEnv(t)
	s := e.source(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.token, []byte("tok2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Issue(ctx); err != nil {
		t.Fatal(err)
	}
	seen := e.fake.Tokens()
	if len(seen) != 2 || seen[0] != "tok1" || seen[1] != "tok2" {
		t.Fatalf("tokens seen: %v", seen)
	}
	if tok, err := s.Token(); err != nil || tok != "tok2" {
		t.Fatalf("Token(): %q %v", tok, err)
	}
	if err := os.WriteFile(e.token, []byte(" \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Token(); err == nil {
		t.Fatal("empty token must error")
	}
	if err := os.Remove(e.token); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Token(); err == nil {
		t.Fatal("missing token must error")
	}
}

func TestRenewalWithInjectedClock(t *testing.T) {
	e := newEnv(t)
	clk := fakelabca.NewFakeClock(time.Now())
	e.fake.SetNow(clk.Now)
	e.cfg.Clock = clk
	e.cfg.Rand = func() float64 { return 0.5 }
	s := e.source(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	first := s.Current()
	waitFor(t, "renewal timer", func() bool { return clk.Pending() >= 2 })
	clk.Advance(29 * time.Minute) // before the 50% mark: trust timer fires, renewal does not
	waitFor(t, "timers re-armed", func() bool { return clk.Pending() >= 2 })
	if s.Current().Renewals != 0 {
		t.Fatal("renewed too early")
	}
	clk.Advance(2 * time.Minute)
	waitFor(t, "renewal", func() bool { return s.Current().Renewals == 1 })
	cur := s.Current()
	if cur.SerialHex == first.SerialHex {
		t.Error("serial did not change after renewal")
	}
	if !cur.NotAfter.After(first.NotAfter) {
		t.Error("NotAfter did not advance")
	}
}

func TestRetryAfterFailure(t *testing.T) {
	e := newEnv(t)
	e.fake.FailNext(503)
	e.fake.FailNext(429)
	s := e.source(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatalf("Start should retry through failures: %v", err)
	}
	if !s.Ready() {
		t.Fatal("not ready after retry")
	}
	if n := len(e.fake.Tokens()); n != 3 {
		t.Errorf("sign attempts %d, want 3", n)
	}
}

func TestStartContextCancelledWhileFailing(t *testing.T) {
	e := newEnv(t)
	for i := 0; i < 1000; i++ {
		e.fake.FailNext(503)
	}
	s := e.source(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := s.Start(ctx); err == nil {
		t.Fatal("want ctx error")
	}
}

func poolOf(pemData []byte) *x509.CertPool {
	p := x509.NewCertPool()
	p.AppendCertsFromPEM(pemData)
	return p
}

func TestTrustBundleReload(t *testing.T) {
	e := newEnv(t)
	clk := fakelabca.NewFakeClock(time.Now())
	e.fake.SetNow(clk.Now)
	e.cfg.Clock = clk
	e.cfg.TrustRefresh = time.Minute
	s := e.source(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	other := fakelabca.New(trustDomain)
	defer other.Close()
	if !s.Roots().Equal(poolOf(e.fake.RootPEM())) {
		t.Fatal("initial pool should hold the fake root")
	}
	// Garbage keeps the old pool.
	if err := os.WriteFile(e.trust, []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "timers", func() bool { return clk.Pending() >= 2 })
	clk.Advance(time.Minute)
	waitFor(t, "timers re-armed", func() bool { return clk.Pending() >= 2 })
	if !s.Roots().Equal(poolOf(e.fake.RootPEM())) {
		t.Fatal("old pool should be kept after parse error")
	}
	// New content swaps the pool.
	if err := os.WriteFile(e.trust, other.RootPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	clk.Advance(time.Minute)
	waitFor(t, "pool swap", func() bool { return s.Roots().Equal(poolOf(other.RootPEM())) })
}

func TestGetCertificateBeforeReady(t *testing.T) {
	e := newEnv(t)
	s := e.source(t)
	if _, err := s.GetCertificate(nil); err == nil {
		t.Error("GetCertificate must fail before first issuance")
	}
	if _, err := s.GetClientCertificate(nil); err == nil {
		t.Error("GetClientCertificate must fail before first issuance")
	}
	if s.Ready() || s.IssuingCA() != nil {
		t.Error("must not be ready")
	}
	if cur := s.Current(); cur.SPIFFEID != "" {
		t.Errorf("current %+v", cur)
	}
	if s.Roots() == nil {
		t.Error("Roots must never be nil")
	}
}

func TestNewValidation(t *testing.T) {
	if _, err := identity.New(identity.Config{}); err == nil {
		t.Error("empty config must fail")
	}
	if _, err := identity.New(identity.Config{LabCA: &labcaapi.Client{}}); err == nil {
		t.Error("missing files must fail")
	}
}
