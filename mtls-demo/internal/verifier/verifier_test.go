package verifier

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Cameloo1/labca/mtls-demo/internal/client"
	"github.com/Cameloo1/labca/mtls-demo/internal/crl"
	"github.com/Cameloo1/labca/mtls-demo/internal/fakelabca"
	"github.com/Cameloo1/labca/mtls-demo/internal/identity"
	"github.com/Cameloo1/labca/mtls-demo/internal/labcaapi"
	"github.com/Cameloo1/labca/mtls-demo/internal/server"
)

const (
	serverID   = "spiffe://labca.test/ns/mtls-demo/sa/demo-server"
	clientID   = "spiffe://labca.test/ns/mtls-demo/sa/demo-client"
	verifierID = "spiffe://labca.test/ns/mtls-demo/sa/mtls-verifier"
	svcURL     = "https://demo-server.mtls-demo.svc:8443/v1/ping"
)

type opts struct {
	allowed        []string
	startCRL       bool
	mutateTLS      func(*tls.Config)
	statusOverride http.Handler
}

type world struct {
	fake      *fakelabca.Server
	srvSrc    *identity.Source
	cliSrc    *identity.Source
	verSrc    *identity.Source
	mtlsAddr  string
	statusURL string
	v         *Verifier
}

func startSource(t *testing.T, fake *fakelabca.Server, token string) *identity.Source {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "token"), []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "trust.pem"), fake.RootPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := identity.New(identity.Config{
		LabCA:           &labcaapi.Client{BaseURL: fake.URL},
		TokenFile:       filepath.Join(dir, "token"),
		TrustBundleFile: filepath.Join(dir, "trust.pem"),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	return s
}

func newWorld(t *testing.T, o opts) *world {
	t.Helper()
	fake := fakelabca.New("labca.test")
	t.Cleanup(fake.Close)
	fake.AddToken("srv", "mtls-demo", "demo-server")
	fake.AddToken("cli", "mtls-demo", "demo-client")
	fake.AddToken("ver", "mtls-demo", "mtls-verifier")
	w := &world{fake: fake}
	w.srvSrc = startSource(t, fake, "srv")
	w.cliSrc = startSource(t, fake, "cli")
	w.verSrc = startSource(t, fake, "ver")

	fetcher := crl.New(crl.Config{
		URL:     fake.URL + "/pki/issuing/crl.der",
		Refresh: 10 * time.Millisecond,
		Issuer:  w.srvSrc.IssuingCA,
	})
	if err := fetcher.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if o.startCRL {
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		go fetcher.Start(ctx)
	}
	allowed := o.allowed
	if allowed == nil {
		allowed = []string{clientID}
	}
	app := server.NewApp(w.srvSrc, fetcher, allowed, t.TempDir(), nil, nil)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := app.NewMTLSServer("")
	if o.mutateTLS != nil {
		o.mutateTLS(srv.TLSConfig)
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	w.mtlsAddr = ln.Addr().String()

	var sh http.Handler = app.StatusHandler()
	if o.statusOverride != nil {
		sh = o.statusOverride
	}
	ss := httptest.NewServer(sh)
	t.Cleanup(ss.Close)
	w.statusURL = ss.URL + "/status.json"

	w.v = &Verifier{
		Cfg: Config{
			ServerURL:            svcURL,
			ServerStatusURL:      w.statusURL,
			DemoClientID:         clientID,
			ExpectedServerID:     serverID,
			AuthorizedCallMaxAge: 120 * time.Second,
			RevokeWaitTimeout:    3 * time.Second,
			RevokePollInterval:   5 * time.Millisecond,
		},
		Src:   w.verSrc,
		LabCA: &labcaapi.Client{BaseURL: fake.URL},
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, w.mtlsAddr)
		},
	}
	return w
}

// demoClientCall makes the real demo client call the server once.
func (w *world) demoClientCall(t *testing.T) {
	t.Helper()
	_, err := client.CallOnce(context.Background(), w.cliSrc, svcURL, serverID, w.v.Dial2())
	if err != nil {
		t.Fatalf("demo client call: %v", err)
	}
}

// Dial2 adapts the verifier's dialer to the client package's type.
func (v *Verifier) Dial2() client.DialFunc { return client.DialFunc(v.Dial) }

func byName(res Results) map[string]Scenario {
	m := map[string]Scenario{}
	for _, s := range res.Scenarios {
		m[s.Name] = s
	}
	return m
}

func TestAllScenariosPassAgainstCorrectServer(t *testing.T) {
	w := newWorld(t, opts{startCRL: true})
	w.demoClientCall(t)
	res := w.v.RunAll(context.Background())
	want := []string{"authorized_client_observed", "no_client_cert_rejected", "forged_identity_rejected", "unauthorized_identity_forbidden", "revoked_identity_rejected"}
	if len(res.Scenarios) != 5 {
		t.Fatalf("got %d scenarios", len(res.Scenarios))
	}
	for i, s := range res.Scenarios {
		if s.Name != want[i] {
			t.Errorf("scenario %d is %q, want %q", i, s.Name, want[i])
		}
		if !s.Passed {
			t.Errorf("%s failed: %s", s.Name, s.Observed)
		}
		if s.Expected == "" || s.Observed == "" {
			t.Errorf("%s: expected/observed must be filled", s.Name)
		}
	}
	if !res.AllPassed {
		t.Error("AllPassed should be true")
	}
	if _, err := time.Parse(time.RFC3339, res.RunAt); err != nil {
		t.Errorf("run_at: %v", err)
	}
	if !strings.Contains(byName(res)["revoked_identity_rejected"].Observed, "rejected") {
		t.Errorf("revocation observed: %s", byName(res)["revoked_identity_rejected"].Observed)
	}
	// JSON keys match the contract.
	b, _ := json.Marshal(res)
	for _, k := range []string{`"run_at"`, `"all_passed"`, `"scenarios"`, `"name"`, `"passed"`, `"expected"`, `"observed"`, `"duration_ms"`} {
		if !strings.Contains(string(b), k) {
			t.Errorf("missing JSON key %s", k)
		}
	}
}

func TestScenario1FailsWithoutAuthorizedCall(t *testing.T) {
	w := newWorld(t, opts{startCRL: true})
	w.v.Cfg.RevokeWaitTimeout = 50 * time.Millisecond
	res := w.v.RunAll(context.Background())
	s := byName(res)["authorized_client_observed"]
	if s.Passed || !strings.Contains(s.Observed, "no authorized call") {
		t.Errorf("scenario 1: %+v", s)
	}
	if res.AllPassed {
		t.Error("AllPassed must be false")
	}
}

func TestScenario1FailsOnStaleCall(t *testing.T) {
	old := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	stub := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, `{"crl":{"number":1},"last_authorized_call":{"client_id":%q,"client_serial_hex":"1","at":%q}}`, clientID, old)
	})
	w := newWorld(t, opts{startCRL: true, statusOverride: stub})
	w.v.Cfg.RevokeWaitTimeout = 50 * time.Millisecond
	s := byName(w.v.RunAll(context.Background()))["authorized_client_observed"]
	if s.Passed {
		t.Errorf("stale call must fail: %+v", s)
	}
	// Wrong client id fails too.
	fresh := time.Now().UTC().Format(time.RFC3339)
	stub2 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, `{"crl":{"number":1},"last_authorized_call":{"client_id":"spiffe://labca.test/ns/x/sa/y","at":%q}}`, fresh)
	})
	w2 := newWorld(t, opts{startCRL: true, statusOverride: stub2})
	w2.v.Cfg.RevokeWaitTimeout = 50 * time.Millisecond
	if s := byName(w2.v.RunAll(context.Background()))["authorized_client_observed"]; s.Passed {
		t.Errorf("wrong client must fail: %+v", s)
	}
	// Status endpoint garbage or error fails.
	bad := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("nope")) })
	w3 := newWorld(t, opts{startCRL: true, statusOverride: bad})
	w3.v.Cfg.RevokeWaitTimeout = 50 * time.Millisecond
	if s := byName(w3.v.RunAll(context.Background()))["authorized_client_observed"]; s.Passed {
		t.Errorf("garbage status must fail: %+v", s)
	}
	down := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) })
	w4 := newWorld(t, opts{startCRL: true, statusOverride: down})
	w4.v.Cfg.RevokeWaitTimeout = 50 * time.Millisecond
	if s := byName(w4.v.RunAll(context.Background()))["authorized_client_observed"]; s.Passed {
		t.Errorf("500 status must fail: %+v", s)
	}
}

func TestScenario2FailsWhenServerAcceptsNoClientCert(t *testing.T) {
	w := newWorld(t, opts{startCRL: true, mutateTLS: func(c *tls.Config) {
		c.GetConfigForClient = nil
		c.ClientAuth = tls.NoClientCert
	}})
	w.v.Cfg.RevokeWaitTimeout = 50 * time.Millisecond
	s := byName(w.v.RunAll(context.Background()))["no_client_cert_rejected"]
	if s.Passed || !strings.Contains(s.Observed, "response") {
		t.Errorf("scenario 2 must fail when the server answers: %+v", s)
	}
}

func TestScenario3FailsWhenServerTrustsForgedCA(t *testing.T) {
	w := newWorld(t, opts{startCRL: true, mutateTLS: func(c *tls.Config) {
		c.GetConfigForClient = nil
		c.ClientAuth = tls.RequireAnyClientCert // accepts any chain, like a server that trusts the forged CA
	}})
	w.v.Cfg.RevokeWaitTimeout = 50 * time.Millisecond
	res := byName(w.v.RunAll(context.Background()))
	if s := res["forged_identity_rejected"]; s.Passed {
		t.Errorf("scenario 3 must fail: %+v", s)
	}
	if s := res["no_client_cert_rejected"]; !s.Passed {
		t.Errorf("scenario 2 should still pass here: %+v", s)
	}
}

func TestScenario4FailsWhenVerifierIDIsAllowed(t *testing.T) {
	w := newWorld(t, opts{startCRL: true, allowed: []string{clientID, verifierID}})
	w.v.Cfg.RevokeWaitTimeout = 50 * time.Millisecond
	s := byName(w.v.RunAll(context.Background()))["unauthorized_identity_forbidden"]
	if s.Passed || !strings.Contains(s.Observed, "200") {
		t.Errorf("scenario 4 must fail: %+v", s)
	}
}

func TestScenario5FailsWhenCRLNeverUpdates(t *testing.T) {
	w := newWorld(t, opts{startCRL: false})
	w.v.Cfg.RevokeWaitTimeout = 100 * time.Millisecond
	s := byName(w.v.RunAll(context.Background()))["revoked_identity_rejected"]
	if s.Passed || !strings.Contains(s.Observed, "crl not updated within 100ms") {
		t.Errorf("scenario 5 must time out: %+v", s)
	}
}

func TestScenario5FailsWhenRevocationNotEnforced(t *testing.T) {
	// Server loads the new CRL (number advances) but does not check it at handshake time.
	w := newWorld(t, opts{startCRL: true, mutateTLS: func(c *tls.Config) {
		c.GetConfigForClient = nil
		c.ClientAuth = tls.RequireAnyClientCert
	}})
	s := byName(w.v.RunAll(context.Background()))["revoked_identity_rejected"]
	if s.Passed {
		t.Errorf("scenario 5 must fail when the revoked cert is still served: %+v", s)
	}
}

func TestUnreachableServerFailsEverything(t *testing.T) {
	w := newWorld(t, opts{startCRL: true})
	w.demoClientCall(t)
	w.v.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, errors.New("connection refused")
	}
	w.v.Cfg.RevokeWaitTimeout = 50 * time.Millisecond
	res := w.v.RunAll(context.Background())
	m := byName(res)
	for _, name := range []string{"no_client_cert_rejected", "forged_identity_rejected", "unauthorized_identity_forbidden", "revoked_identity_rejected"} {
		s := m[name]
		if s.Passed {
			t.Errorf("%s passed against an unreachable server", name)
		}
		if !strings.Contains(s.Observed, "unreachable") {
			t.Errorf("%s observed should mention unreachable: %q", name, s.Observed)
		}
	}
	if res.AllPassed {
		t.Error("AllPassed must be false")
	}
}

func TestRealUnreachablePort(t *testing.T) {
	w := newWorld(t, opts{startCRL: true})
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	w.v.Dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	a := w.v.attempt(context.Background(), nil)
	if a.Kind != kindUnreachable {
		t.Errorf("got %+v", a)
	}
}

func TestRunScenarioRecoversPanic(t *testing.T) {
	v := &Verifier{}
	s := v.runScenario("boom", "never", func() (bool, string) { panic("kaboom") })
	if s.Passed || !strings.Contains(s.Observed, "panic: kaboom") || s.Name != "boom" {
		t.Errorf("%+v", s)
	}
}

func TestIsTLSRejection(t *testing.T) {
	remote := &net.OpError{Op: "remote error", Err: errors.New("tls: bad certificate")}
	cases := []struct {
		name string
		err  error
		done bool
		want bool
	}{
		{"remote alert", remote, false, true},
		{"cert verification", &tls.CertificateVerificationError{Err: errors.New("x")}, false, false},
		{"tls text", errors.New("local error: tls: handshake failure"), false, false},
		{"EPIPE after handshake", &net.OpError{Op: "write", Err: syscall.EPIPE}, true, true},
		{"eof after handshake", io.EOF, true, true},
		{"unexpected eof after handshake", io.ErrUnexpectedEOF, true, true},
		{"reset after handshake", &net.OpError{Op: "read", Err: syscall.ECONNRESET}, true, true},
		{"eof before handshake", io.EOF, false, false},
		{"plain error", errors.New("boom"), true, false},
		{"timeout", &net.OpError{Op: "read", Err: timeoutErr{}}, true, false},
	}
	for _, c := range cases {
		if got := isTLSRejection(c.err, c.done); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string { return "i/o timeout" }
func (timeoutErr) Timeout() bool { return true }

func TestForgeProducesUntrustedClientCert(t *testing.T) {
	w := newWorld(t, opts{startCRL: true})
	c, err := forge(clientID)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Certificate) != 2 {
		t.Fatalf("chain length %d", len(c.Certificate))
	}
	leaf, _ := x509.ParseCertificate(c.Certificate[0])
	ca, _ := x509.ParseCertificate(c.Certificate[1])
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != clientID {
		t.Errorf("forged SAN %v", leaf.URIs)
	}
	inter := x509.NewCertPool()
	inter.AddCert(ca)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: w.verSrc.Roots(), Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err == nil {
		t.Error("forged cert must not verify against the real roots")
	}
	if _, err := forge("::bad::"); err == nil {
		t.Error("bad ID must error")
	}
}

func kubeFixture(t *testing.T, handler http.HandlerFunc) Config {
	t.Helper()
	ts := httptest.NewTLSServer(handler)
	t.Cleanup(ts.Close)
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	tokFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokFile, []byte("kube-secret-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return Config{KubeAPIURL: ts.URL, KubeCAFile: caFile, KubeTokenFile: tokFile, PodNamespace: "mtls-demo", StatusConfigMap: "mtls-status"}
}

func TestWriteConfigMapPatch(t *testing.T) {
	var gotMethod, gotPath, gotAuth, gotCT string
	var gotBody []byte
	var gotTLS uint16
	cfg := kubeFixture(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		gotAuth, gotCT = r.Header.Get("Authorization"), r.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(r.Body)
		gotTLS = r.TLS.Version
		_, _ = w.Write([]byte(`{}`))
	})
	res := Results{RunAt: "2026-01-01T00:00:00Z", AllPassed: true, Scenarios: []Scenario{{Name: "a", Passed: true, Expected: "e", Observed: "o", DurationMS: 4}}}
	if err := WriteConfigMap(context.Background(), cfg, res); err != nil {
		t.Fatal(err)
	}
	if gotMethod != "PATCH" || gotPath != "/api/v1/namespaces/mtls-demo/configmaps/mtls-status" {
		t.Errorf("request %s %s", gotMethod, gotPath)
	}
	if gotAuth != "Bearer kube-secret-token" || gotCT != "application/merge-patch+json" {
		t.Errorf("headers %q %q", gotAuth, gotCT)
	}
	if gotTLS < tls.VersionTLS12 {
		t.Errorf("tls version %x", gotTLS)
	}
	var body struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(gotBody, &body); err != nil {
		t.Fatal(err)
	}
	var back Results
	if err := json.Unmarshal([]byte(body.Data["results.json"]), &back); err != nil {
		t.Fatalf("results.json is not a JSON string: %v", err)
	}
	if back.RunAt != res.RunAt || !back.AllPassed || len(back.Scenarios) != 1 || back.Scenarios[0] != res.Scenarios[0] {
		t.Errorf("round trip: %+v", back)
	}
}

func TestWriteConfigMapErrors(t *testing.T) {
	cfg := kubeFixture(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(403) })
	if err := WriteConfigMap(context.Background(), cfg, Results{}); err == nil || !strings.Contains(err.Error(), "403") {
		t.Errorf("non-200 must error, got %v", err)
	}
	bad := cfg
	bad.KubeCAFile = filepath.Join(t.TempDir(), "missing")
	if err := WriteConfigMap(context.Background(), bad, Results{}); err == nil {
		t.Error("missing CA must error")
	}
	bad = cfg
	bad.KubeTokenFile = filepath.Join(t.TempDir(), "missing")
	if err := WriteConfigMap(context.Background(), bad, Results{}); err == nil {
		t.Error("missing token must error")
	}
	empty := filepath.Join(t.TempDir(), "empty.crt")
	_ = os.WriteFile(empty, []byte("junk"), 0o600)
	bad = cfg
	bad.KubeCAFile = empty
	if err := WriteConfigMap(context.Background(), bad, Results{}); err == nil {
		t.Error("CA without certs must error")
	}
	// An API server that does not chain to the CA file fails closed.
	other := httptest.NewTLSServer(http.NotFoundHandler())
	defer other.Close()
	bad = cfg
	bad.KubeAPIURL = other.URL
	if err := WriteConfigMap(context.Background(), bad, Results{}); err == nil {
		t.Error("untrusted API server must error")
	}
}

func TestConfigFromEnv(t *testing.T) {
	t.Setenv("DEMO_CLIENT_ID", "")
	if _, err := ConfigFromEnv(); err == nil {
		t.Error("missing DEMO_CLIENT_ID")
	}
	t.Setenv("DEMO_CLIENT_ID", clientID)
	t.Setenv("EXPECTED_SERVER_ID", "bad")
	if _, err := ConfigFromEnv(); err == nil {
		t.Error("invalid EXPECTED_SERVER_ID")
	}
	t.Setenv("EXPECTED_SERVER_ID", serverID)
	t.Setenv("POD_NAMESPACE", "")
	if _, err := ConfigFromEnv(); err == nil {
		t.Error("missing POD_NAMESPACE")
	}
	t.Setenv("POD_NAMESPACE", "mtls-demo")
	t.Setenv("KUBE_API_URL", "")
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")
	if _, err := ConfigFromEnv(); err == nil {
		t.Error("missing kube API location")
	}
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "443")
	t.Setenv("REVOKE_POLL_INTERVAL", "x")
	if _, err := ConfigFromEnv(); err == nil {
		t.Error("bad REVOKE_POLL_INTERVAL")
	}
	t.Setenv("REVOKE_POLL_INTERVAL", "")
	t.Setenv("REVOKE_WAIT_TIMEOUT", "-1s")
	if _, err := ConfigFromEnv(); err == nil {
		t.Error("bad REVOKE_WAIT_TIMEOUT")
	}
	t.Setenv("REVOKE_WAIT_TIMEOUT", "")
	t.Setenv("AUTHORIZED_CALL_MAX_AGE", "x")
	if _, err := ConfigFromEnv(); err == nil {
		t.Error("bad AUTHORIZED_CALL_MAX_AGE")
	}
	t.Setenv("AUTHORIZED_CALL_MAX_AGE", "")
	c, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if c.KubeAPIURL != "https://10.0.0.1:443" || c.AuthorizedCallMaxAge != 120*time.Second || c.RevokeWaitTimeout != 120*time.Second ||
		c.RevokePollInterval != 2*time.Second || c.StatusConfigMap != "mtls-status" || c.KubeTokenFile != "/var/run/secrets/kube-api/token" {
		t.Errorf("defaults: %+v", c)
	}
}

func TestRunFailsOnBadConfig(t *testing.T) {
	t.Setenv("DEMO_CLIENT_ID", "")
	if err := Run(context.Background(), nil); err == nil {
		t.Error("Run must fail without required env")
	}
}

func TestRunFailsWhenIdentityUnavailable(t *testing.T) {
	t.Setenv("DEMO_CLIENT_ID", clientID)
	t.Setenv("EXPECTED_SERVER_ID", serverID)
	t.Setenv("POD_NAMESPACE", "mtls-demo")
	t.Setenv("KUBE_API_URL", "https://127.0.0.1:1")
	t.Setenv("TRUST_BUNDLE_FILE", filepath.Join(t.TempDir(), "missing.pem"))
	t.Setenv("TOKEN_FILE", filepath.Join(t.TempDir(), "missing"))
	if err := Run(context.Background(), nil); err == nil {
		t.Error("Run must fail when the trust bundle cannot be loaded")
	}
}

func TestServerCertFromUntrustedCAIsError(t *testing.T) {
	w := newWorld(t, opts{startCRL: true})
	other := fakelabca.New("labca.test")
	t.Cleanup(other.Close)
	other.AddToken("ver", "mtls-demo", "mtls-verifier")
	w.v.Src = startSource(t, other, "ver")

	own, err := w.v.Src.GetClientCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	a := w.v.attempt(context.Background(), own)
	if a.Kind != kindError || !strings.HasPrefix(a.Detail, "local tls error: ") {
		t.Fatalf("attempt = %+v, want kindError with local tls error prefix", a)
	}
	res := w.v.RunAll(context.Background())
	m := byName(res)
	for _, n := range []string{"no_client_cert_rejected", "forged_identity_rejected", "revoked_identity_rejected"} {
		if m[n].Passed {
			t.Errorf("%s must not pass when the server certificate is untrusted: %s", n, m[n].Observed)
		}
	}
	if res.AllPassed {
		t.Error("AllPassed must be false")
	}
}
