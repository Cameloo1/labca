package server_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Cameloo1/labca/mtls-demo/internal/crl"
	"github.com/Cameloo1/labca/mtls-demo/internal/fakelabca"
	"github.com/Cameloo1/labca/mtls-demo/internal/identity"
	"github.com/Cameloo1/labca/mtls-demo/internal/labcaapi"
	"github.com/Cameloo1/labca/mtls-demo/internal/server"
)

const (
	trustDomain = "labca.test"
	serverID    = "spiffe://labca.test/ns/mtls-demo/sa/demo-server"
	clientID    = "spiffe://labca.test/ns/mtls-demo/sa/demo-client"
	otherID     = "spiffe://labca.test/ns/mtls-demo/sa/mtls-verifier"
	sniName     = "demo-server.mtls-demo.svc"
)

type env struct {
	fake    *fakelabca.Server
	dir     string
	srvSrc  *identity.Source
	cliSrc  *identity.Source
	othSrc  *identity.Source
	fetcher *crl.Fetcher
	app     *server.App
	addr    string
}

func startSource(t *testing.T, fake *fakelabca.Server, token string) *identity.Source {
	t.Helper()
	dir := t.TempDir()
	tokFile := filepath.Join(dir, "token")
	trustFile := filepath.Join(dir, "trust.pem")
	if err := os.WriteFile(tokFile, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(trustFile, fake.RootPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := identity.New(identity.Config{
		LabCA:           &labcaapi.Client{BaseURL: fake.URL},
		TokenFile:       tokFile,
		TrustBundleFile: trustFile,
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

func newEnv(t *testing.T) *env {
	t.Helper()
	fake := fakelabca.New(trustDomain)
	t.Cleanup(fake.Close)
	fake.AddToken("srv", "mtls-demo", "demo-server")
	fake.AddToken("cli", "mtls-demo", "demo-client")
	fake.AddToken("oth", "mtls-demo", "mtls-verifier")
	e := &env{fake: fake, dir: t.TempDir()}
	e.srvSrc = startSource(t, fake, "srv")
	e.cliSrc = startSource(t, fake, "cli")
	e.othSrc = startSource(t, fake, "oth")
	e.fetcher = crl.New(crl.Config{
		URL:    fake.URL + "/pki/issuing/crl.der",
		Issuer: e.srvSrc.IssuingCA,
	})
	if err := e.fetcher.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.app = server.NewApp(e.srvSrc, e.fetcher, []string{clientID}, e.dir, nil, nil)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := e.app.NewMTLSServer("")
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	e.addr = ln.Addr().String()
	return e
}

func (e *env) ping(clientCfg *tls.Config) (int, map[string]any, error) {
	clientCfg.MinVersion = tls.VersionTLS13
	clientCfg.ServerName = sniName
	if clientCfg.RootCAs == nil {
		clientCfg.RootCAs = e.cliSrc.Roots()
	}
	tr := &http.Transport{TLSClientConfig: clientCfg, DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	resp, err := c.Get("https://" + e.addr + "/v1/ping")
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return resp.StatusCode, m, nil
}

func clientCfg(src *identity.Source) *tls.Config {
	return &tls.Config{GetClientCertificate: src.GetClientCertificate}
}

func TestAllowedClientGets200(t *testing.T) {
	e := newEnv(t)
	status, body, err := e.ping(clientCfg(e.cliSrc))
	if err != nil || status != 200 {
		t.Fatalf("status %d err %v", status, err)
	}
	if body["server_id"] != serverID || body["client_id"] != clientID {
		t.Errorf("body %v", body)
	}
	if body["client_serial_hex"] != e.cliSrc.Current().SerialHex {
		t.Errorf("serial %v", body["client_serial_hex"])
	}
	if _, err := time.Parse(time.RFC3339, body["time"].(string)); err != nil {
		t.Errorf("time: %v", err)
	}
}

func TestUnauthorizedValidClientForbidden(t *testing.T) {
	e := newEnv(t)
	status, body, err := e.ping(clientCfg(e.othSrc))
	if err != nil {
		t.Fatal(err)
	}
	if status != 403 || body["error"] != "forbidden" || body["client_id"] != otherID || body["detail"] != "client identity is not authorized" {
		t.Errorf("status %d body %v", status, body)
	}
}

func TestRevokedClientRejected(t *testing.T) {
	e := newEnv(t)
	iss, err := e.cliSrc.Issue(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	cfg := func() *tls.Config {
		return &tls.Config{GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &iss.Cert, nil }}
	}
	if status, _, err := e.ping(cfg()); err != nil || status != 200 {
		t.Fatalf("before revocation: %d %v", status, err)
	}
	e.fake.RevokeSerial(iss.Leaf.SerialNumber.Text(16))
	if err := e.fetcher.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	status, _, err := e.ping(cfg())
	if err == nil {
		t.Fatalf("revoked client got status %d", status)
	}
	if !strings.Contains(err.Error(), "tls") {
		t.Errorf("expected a TLS-level rejection, got %v", err)
	}
}

func TestNoClientCertRejected(t *testing.T) {
	e := newEnv(t)
	if status, _, err := e.ping(&tls.Config{}); err == nil {
		t.Fatalf("no cert accepted with status %d", status)
	}
}

func forge(t *testing.T, id string) *tls.Certificate {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Forged CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	u, _ := url.Parse(id)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "forged"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs: []*url.URL{u},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: key}
}

func TestForgedClientRejected(t *testing.T) {
	e := newEnv(t)
	f := forge(t, clientID)
	cfg := &tls.Config{GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return f, nil }}
	if status, _, err := e.ping(cfg); err == nil {
		t.Fatalf("forged client accepted with status %d", status)
	}
}

func TestStaleCRLRejectsEveryone(t *testing.T) {
	e := newEnv(t)
	clk := fakelabca.NewFakeClock(time.Now())
	e.fake.SetNextUpdate(time.Now().Add(time.Hour))
	stale := crl.New(crl.Config{URL: e.fake.URL + "/pki/issuing/crl.der", Issuer: e.srvSrc.IssuingCA, Clock: clk})
	if err := stale.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	clk.Advance(2 * time.Hour)
	app := server.NewApp(e.srvSrc, stale, []string{clientID}, e.dir, nil, nil)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	srv := app.NewMTLSServer("")
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	defer srv.Close()
	e.addr = ln.Addr().String()
	if status, _, err := e.ping(clientCfg(e.cliSrc)); err == nil {
		t.Fatalf("stale CRL must fail closed, got %d", status)
	}
}

func TestMTLSRoutes(t *testing.T) {
	e := newEnv(t)
	h := e.app.MTLSHandler()
	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{"GET", "/nope", 404},
		{"POST", "/v1/ping", 405},
		{"GET", "/v1/ping", 403}, // no TLS state at all
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
		if rec.Code != tc.want {
			t.Errorf("%s %s: %d", tc.method, tc.path, rec.Code)
		}
		if tc.want == 404 && !strings.Contains(rec.Body.String(), `"not_found"`) {
			t.Errorf("404 body %q", rec.Body.String())
		}
	}
}

func getStatus(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
	return rec
}

func TestStatusJSONShape(t *testing.T) {
	e := newEnv(t)
	h := e.app.StatusHandler()
	rec := getStatus(t, h, "/status.json")
	if rec.Code != 200 || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("code %d headers %v", rec.Code, rec.Header())
	}
	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"generated_at", "server", "crl", "last_authorized_call", "verifier"} {
		if _, ok := doc[k]; !ok {
			t.Errorf("missing key %q", k)
		}
	}
	srvDoc := doc["server"].(map[string]any)
	for _, k := range []string{"spiffe_id", "serial_hex", "not_after", "renewals"} {
		if _, ok := srvDoc[k]; !ok {
			t.Errorf("missing server.%s", k)
		}
	}
	if srvDoc["spiffe_id"] != serverID {
		t.Errorf("server id %v", srvDoc["spiffe_id"])
	}
	crlDoc := doc["crl"].(map[string]any)
	for _, k := range []string{"number", "this_update", "next_update", "fetched_at", "revoked_count"} {
		if _, ok := crlDoc[k]; !ok {
			t.Errorf("missing crl.%s", k)
		}
	}
	if crlDoc["number"].(float64) != 1 {
		t.Errorf("crl number %v", crlDoc["number"])
	}
	if doc["verifier"] != nil || doc["last_authorized_call"] != nil {
		t.Errorf("verifier and last call should be null: %v %v", doc["verifier"], doc["last_authorized_call"])
	}

	// A call populates last_authorized_call.
	if status, _, err := e.ping(clientCfg(e.cliSrc)); err != nil || status != 200 {
		t.Fatal(status, err)
	}
	_ = json.Unmarshal(getStatus(t, h, "/status.json").Body.Bytes(), &doc)
	lc, ok := doc["last_authorized_call"].(map[string]any)
	if !ok || lc["client_id"] != clientID || lc["client_serial_hex"] == "" || lc["at"] == "" {
		t.Errorf("last_authorized_call %v", doc["last_authorized_call"])
	}

	// results.json populates verifier.
	results := `{"run_at":"2026-01-01T00:00:00Z","all_passed":true,"scenarios":[{"name":"s1","passed":true,"expected":"e","observed":"o","duration_ms":3}]}`
	if err := os.WriteFile(filepath.Join(e.dir, "results.json"), []byte(results), 0o600); err != nil {
		t.Fatal(err)
	}
	doc = nil
	_ = json.Unmarshal(getStatus(t, h, "/status.json").Body.Bytes(), &doc)
	v, ok := doc["verifier"].(map[string]any)
	if !ok || v["run_at"] != "2026-01-01T00:00:00Z" || v["all_passed"] != true || len(v["scenarios"].([]any)) != 1 {
		t.Errorf("verifier %v", doc["verifier"])
	}
}

func TestVerifierResultsIgnoredWhenInvalid(t *testing.T) {
	e := newEnv(t)
	h := e.app.StatusHandler()
	for _, content := range []string{"", "{}", "not json", `{"all_passed":true}`} {
		if err := os.WriteFile(filepath.Join(e.dir, "results.json"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		_ = json.Unmarshal(getStatus(t, h, "/status.json").Body.Bytes(), &doc)
		if doc["verifier"] != nil {
			t.Errorf("content %q: verifier should be null, got %v", content, doc["verifier"])
		}
	}
}

func TestStatusPageAndHeaders(t *testing.T) {
	e := newEnv(t)
	h := e.app.StatusHandler()
	runAt := time.Now().Add(-5 * time.Minute).UTC().Format(time.RFC3339)
	results := `{"run_at":"` + runAt + `","all_passed":false,"scenarios":[{"name":"<b>x</b>","passed":false,"expected":"e","observed":"o","duration_ms":3}]}`
	if err := os.WriteFile(filepath.Join(e.dir, "results.json"), []byte(results), 0o600); err != nil {
		t.Fatal(err)
	}
	rec := getStatus(t, h, "/")
	body := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(body, `http-equiv="refresh" content="30"`) {
		t.Fatalf("code %d", rec.Code)
	}
	if strings.Contains(strings.ToLower(body), "<script") {
		t.Error("page must not contain JavaScript")
	}
	if strings.Contains(body, "<b>x</b>") || !strings.Contains(body, "&lt;b&gt;x&lt;/b&gt;") {
		t.Error("scenario name must be HTML-escaped")
	}
	if !strings.Contains(body, "5 minutes ago") || !strings.Contains(body, serverID) {
		t.Errorf("page missing expected content")
	}
	for _, p := range []string{"/", "/status.json", "/healthz", "/readyz", "/missing"} {
		hd := getStatus(t, h, p).Header()
		if hd.Get("Content-Security-Policy") != "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'" ||
			hd.Get("X-Content-Type-Options") != "nosniff" || hd.Get("X-Frame-Options") != "DENY" || hd.Get("Referrer-Policy") != "no-referrer" {
			t.Errorf("%s: security headers %v", p, hd)
		}
	}
	// Page also renders with nothing loaded.
	rec = getStatus(t, h, "/")
	_ = rec
}

func TestStatusRoutes404AndHealth(t *testing.T) {
	e := newEnv(t)
	h := e.app.StatusHandler()
	if rec := getStatus(t, h, "/unknown"); rec.Code != 404 {
		t.Errorf("unknown path: %d", rec.Code)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/status.json", nil))
	if rec.Code != 404 {
		t.Errorf("POST: %d", rec.Code)
	}
	if rec := getStatus(t, h, "/healthz"); rec.Code != 200 || rec.Body.String() != "ok" {
		t.Errorf("healthz: %d %q", rec.Code, rec.Body.String())
	}
	if rec := getStatus(t, h, "/readyz"); rec.Code != 200 {
		t.Errorf("readyz: %d", rec.Code)
	}
}

func TestReadyz503BeforeReady(t *testing.T) {
	fake := fakelabca.New(trustDomain)
	defer fake.Close()
	dir := t.TempDir()
	src, err := identity.New(identity.Config{
		LabCA:           &labcaapi.Client{BaseURL: fake.URL},
		TokenFile:       filepath.Join(dir, "token"),
		TrustBundleFile: filepath.Join(dir, "trust.pem"),
	})
	if err != nil {
		t.Fatal(err)
	}
	fetcher := crl.New(crl.Config{URL: fake.URL, Issuer: src.IssuingCA})
	app := server.NewApp(src, fetcher, []string{clientID}, dir, nil, nil)
	h := app.StatusHandler()
	rec := getStatus(t, h, "/readyz")
	if rec.Code != 503 || rec.Body.Len() == 0 {
		t.Errorf("readyz before ready: %d %q", rec.Code, rec.Body.String())
	}
	if rec := getStatus(t, h, "/healthz"); rec.Code != 200 {
		t.Errorf("healthz must be 200 before ready, got %d", rec.Code)
	}
	// status.json and the page still render, with nulls.
	var doc map[string]any
	if err := json.Unmarshal(getStatus(t, h, "/status.json").Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["server"].(map[string]any)["not_after"] != nil || doc["crl"].(map[string]any)["this_update"] != nil {
		t.Errorf("zero times must render as null: %v", doc)
	}
	if rec := getStatus(t, h, "/"); rec.Code != 200 || !strings.Contains(rec.Body.String(), "No verifier results yet") {
		t.Errorf("page before ready: %d", rec.Code)
	}
	// TLS handshakes fail until identity exists.
	cfg := app.TLSConfig()
	if _, err := cfg.GetCertificate(nil); err == nil {
		t.Error("GetCertificate must fail before identity exists")
	}
}

func TestConfigFromEnv(t *testing.T) {
	t.Setenv("ALLOWED_CLIENT_IDS", "")
	if _, err := server.ConfigFromEnv(); err == nil {
		t.Error("missing ALLOWED_CLIENT_IDS must fail")
	}
	t.Setenv("ALLOWED_CLIENT_IDS", "spiffe://Bad/x")
	if _, err := server.ConfigFromEnv(); err == nil {
		t.Error("invalid ID must fail")
	}
	t.Setenv("ALLOWED_CLIENT_IDS", clientID+" , "+otherID)
	t.Setenv("CRL_REFRESH", "banana")
	if _, err := server.ConfigFromEnv(); err == nil {
		t.Error("bad CRL_REFRESH must fail")
	}
	t.Setenv("CRL_REFRESH", "")
	c, err := server.ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if len(c.AllowedClientIDs) != 2 || c.MTLSAddr != ":8443" || c.StatusAddr != ":8080" || c.CRLRefresh != 30*time.Second ||
		c.CRLURL != "http://labca.labca-system.svc.cluster.local:8000/pki/issuing/crl.der" || c.StatusDir != "/etc/mtls-status" {
		t.Errorf("defaults: %+v", c)
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func TestRunServesAndShutsDown(t *testing.T) {
	fake := fakelabca.New(trustDomain)
	defer fake.Close()
	fake.AddToken("srv", "mtls-demo", "demo-server")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "token"), []byte("srv"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "trust.pem"), fake.RootPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	statusAddr := freeAddr(t)
	t.Setenv("LABCA_URL", fake.URL)
	t.Setenv("TOKEN_FILE", filepath.Join(dir, "token"))
	t.Setenv("TRUST_BUNDLE_FILE", filepath.Join(dir, "trust.pem"))
	t.Setenv("ALLOWED_CLIENT_IDS", clientID)
	t.Setenv("STATUS_DIR", dir)
	t.Setenv("MTLS_ADDR", freeAddr(t))
	t.Setenv("STATUS_ADDR", statusAddr)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx, nil) }()
	deadline := time.Now().Add(10 * time.Second)
	ready := false
	for time.Now().Before(deadline) && !ready {
		resp, err := http.Get("http://" + statusAddr + "/readyz")
		if err == nil {
			ready = resp.StatusCode == 200
			resp.Body.Close()
		}
		if !ready {
			time.Sleep(20 * time.Millisecond)
		}
	}
	if !ready {
		cancel()
		t.Fatal("server never became ready")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

func TestSiblingIssuerClientRejected(t *testing.T) {
	e := newEnv(t)
	sibCert, sibKey := e.fake.NewSiblingIssuer()
	leaf, err := fakelabca.IssueLeaf(sibCert, sibKey, clientID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	status, _, err := e.ping(&tls.Config{GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return leaf, nil }})
	if err == nil {
		t.Fatalf("sibling-issued client got status %d", status)
	}
	if status, _, err := e.ping(clientCfg(e.cliSrc)); err != nil || status != 200 {
		t.Fatalf("normal client: %d %v", status, err)
	}
}
