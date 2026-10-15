package client_test

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Cameloo1/labca/mtls-demo/internal/client"
	"github.com/Cameloo1/labca/mtls-demo/internal/fakelabca"
	"github.com/Cameloo1/labca/mtls-demo/internal/identity"
	"github.com/Cameloo1/labca/mtls-demo/internal/labcaapi"
)

const (
	serverID = "spiffe://labca.test/ns/mtls-demo/sa/demo-server"
	clientID = "spiffe://labca.test/ns/mtls-demo/sa/demo-client"
)

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

func setup(t *testing.T) (cli *identity.Source, serverURL string, dial client.DialFunc) {
	t.Helper()
	fake := fakelabca.New("labca.test")
	t.Cleanup(fake.Close)
	fake.AddToken("srv", "mtls-demo", "demo-server")
	fake.AddToken("cli", "mtls-demo", "demo-client")
	srvSrc := startSource(t, fake, "srv")
	cli = startSource(t, fake, "cli")
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = w.Write([]byte(`{"server_id":"` + serverID + `"}`))
	}))
	ts.TLS = &tls.Config{
		MinVersion:     tls.VersionTLS13,
		GetCertificate: srvSrc.GetCertificate,
		ClientAuth:     tls.RequireAndVerifyClientCert,
		ClientCAs:      srvSrc.Roots(),
	}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	// The certificate carries DNS SANs for the service name; reach the loopback listener under that name.
	addr := ts.Listener.Addr().String()
	dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	return cli, "https://demo-server.mtls-demo.svc:8443/v1/ping", dial
}

func TestCallOnceMatchingServerID(t *testing.T) {
	cli, url, dial := setup(t)
	res, err := client.CallOnce(context.Background(), cli, url, serverID, dial)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != 200 || res.ServerID != serverID {
		t.Errorf("result %+v", res)
	}
}

func TestCallOnceWrongServerID(t *testing.T) {
	cli, url, dial := setup(t)
	_, err := client.CallOnce(context.Background(), cli, url, clientID, dial)
	if err == nil {
		t.Fatal("server with a different SPIFFE ID must be rejected")
	}
	if !strings.Contains(err.Error(), "does not match expected") {
		t.Errorf("error should come from VerifyConnection: %v", err)
	}
}

func TestCallOnceNonOKStatus(t *testing.T) {
	cli, _, _ := setup(t)
	ts := httptest.NewServer(http.NotFoundHandler())
	defer ts.Close()
	if _, err := client.CallOnce(context.Background(), cli, ts.URL, serverID, nil); err == nil {
		t.Fatal("plain HTTP server must fail the TLS handshake")
	}
}

func TestHealthHandler(t *testing.T) {
	cli, _, _ := setup(t)
	rec := httptest.NewRecorder()
	client.HealthHandler(cli).ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != 200 {
		t.Errorf("ready: %d", rec.Code)
	}
	notReady, err := identity.New(identity.Config{LabCA: &labcaapi.Client{}, TokenFile: "x", TrustBundleFile: "y"})
	if err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	client.HealthHandler(notReady).ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != 503 {
		t.Errorf("not ready: %d", rec.Code)
	}
}

func TestConfigFromEnv(t *testing.T) {
	t.Setenv("EXPECTED_SERVER_ID", "")
	if _, err := client.ConfigFromEnv(); err == nil {
		t.Error("missing EXPECTED_SERVER_ID must fail")
	}
	t.Setenv("EXPECTED_SERVER_ID", "https://nope")
	if _, err := client.ConfigFromEnv(); err == nil {
		t.Error("invalid EXPECTED_SERVER_ID must fail")
	}
	t.Setenv("EXPECTED_SERVER_ID", serverID)
	t.Setenv("INTERVAL", "0s")
	if _, err := client.ConfigFromEnv(); err == nil {
		t.Error("bad INTERVAL must fail")
	}
	t.Setenv("INTERVAL", "")
	c, err := client.ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if c.Interval != 15*time.Second || c.HealthAddr != ":8081" || c.ServerURL != "https://demo-server.mtls-demo.svc.cluster.local:8443/v1/ping" {
		t.Errorf("defaults %+v", c)
	}
}
