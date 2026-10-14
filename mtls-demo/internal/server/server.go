// Package server implements the demo-server subcommand: an mTLS listener
// that authorizes peers by SPIFFE ID plus a plain HTTP status listener.
package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Cameloo1/labca/mtls-demo/internal/crl"
	"github.com/Cameloo1/labca/mtls-demo/internal/identity"
	"github.com/Cameloo1/labca/mtls-demo/internal/labcaapi"
	"github.com/Cameloo1/labca/mtls-demo/internal/spiffe"
)

// Config is the server's environment-derived configuration.
type Config struct {
	LabCAURL         string
	TokenFile        string
	TrustBundleFile  string
	CRLURL           string
	CRLRefresh       time.Duration
	AllowedClientIDs []string
	StatusDir        string
	MTLSAddr         string
	StatusAddr       string
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// ConfigFromEnv reads and validates the environment.
func ConfigFromEnv() (Config, error) {
	c := Config{
		LabCAURL:        getenv("LABCA_URL", "http://labca.labca-system.svc.cluster.local:8000"),
		TokenFile:       getenv("TOKEN_FILE", "/var/run/secrets/labca/token"),
		TrustBundleFile: getenv("TRUST_BUNDLE_FILE", "/etc/labca/trust/trust-bundle.pem"),
		StatusDir:       getenv("STATUS_DIR", "/etc/mtls-status"),
		MTLSAddr:        getenv("MTLS_ADDR", ":8443"),
		StatusAddr:      getenv("STATUS_ADDR", ":8080"),
	}
	c.CRLURL = getenv("CRL_URL", strings.TrimRight(c.LabCAURL, "/")+"/pki/issuing/crl.der")
	d, err := time.ParseDuration(getenv("CRL_REFRESH", "30s"))
	if err != nil || d <= 0 {
		return Config{}, fmt.Errorf("CRL_REFRESH is not a positive duration")
	}
	c.CRLRefresh = d
	raw := os.Getenv("ALLOWED_CLIENT_IDS")
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, err := spiffe.Parse(p); err != nil {
			return Config{}, fmt.Errorf("ALLOWED_CLIENT_IDS: %w", err)
		}
		c.AllowedClientIDs = append(c.AllowedClientIDs, p)
	}
	if len(c.AllowedClientIDs) == 0 {
		return Config{}, errors.New("ALLOWED_CLIENT_IDS is required")
	}
	return c, nil
}

type lastCall struct {
	ClientID        string `json:"client_id"`
	ClientSerialHex string `json:"client_serial_hex"`
	At              string `json:"at"`
}

// App holds the state shared by both listeners.
type App struct {
	src       *identity.Source
	fetcher   *crl.Fetcher
	allowed   map[string]struct{}
	statusDir string
	clock     identity.Clock
	logger    *slog.Logger
	last      atomic.Pointer[lastCall]
}

// NewApp builds the handlers' shared state. clock and logger may be nil.
func NewApp(src *identity.Source, fetcher *crl.Fetcher, allowedIDs []string, statusDir string, clock identity.Clock, logger *slog.Logger) *App {
	if clock == nil {
		clock = identity.RealClock()
	}
	if logger == nil {
		logger = slog.Default()
	}
	allowed := make(map[string]struct{}, len(allowedIDs))
	for _, id := range allowedIDs {
		allowed[id] = struct{}{}
	}
	return &App{src: src, fetcher: fetcher, allowed: allowed, statusDir: statusDir, clock: clock, logger: logger}
}

// TLSConfig returns the mTLS listener configuration.
func (a *App) TLSConfig() *tls.Config {
	base := &tls.Config{
		MinVersion:     tls.VersionTLS13,
		ClientAuth:     tls.RequireAndVerifyClientCert,
		GetCertificate: a.src.GetCertificate,
	}
	base.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		c := base.Clone()
		c.GetConfigForClient = nil
		c.ClientCAs = a.src.Roots()
		c.VerifyConnection = a.verifyConnection
		return c, nil
	}
	return base
}

func (a *App) verifyConnection(cs tls.ConnectionState) error {
	if len(cs.VerifiedChains) == 0 || len(cs.VerifiedChains[0]) < 2 {
		return errors.New("client certificate chain was not verified")
	}
	chain := cs.VerifiedChains[0]
	revoked, err := a.fetcher.Check(chain[0], chain[1])
	if err != nil {
		return fmt.Errorf("revocation check failed closed: %w", err)
	}
	if revoked {
		return errors.New("client certificate is revoked")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// MTLSHandler serves the routes behind the mTLS listener.
func (a *App) MTLSHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/ping" {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found", "detail": "not found"})
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed", "detail": "GET only"})
			return
		}
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden", "detail": "client identity is not authorized", "client_id": ""})
			return
		}
		peer := r.TLS.PeerCertificates[0]
		id, err := spiffe.FromCertificate(peer)
		if err != nil {
			id = ""
		}
		if _, ok := a.allowed[id]; !ok || id == "" {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden", "detail": "client identity is not authorized", "client_id": id})
			return
		}
		now := a.clock.Now().UTC().Format(time.RFC3339)
		serialHex := bigHex(peer.SerialNumber)
		a.last.Store(&lastCall{ClientID: id, ClientSerialHex: serialHex, At: now})
		writeJSON(w, http.StatusOK, map[string]string{
			"server_id":         a.src.Current().SPIFFEID,
			"client_id":         id,
			"client_serial_hex": serialHex,
			"time":              now,
		})
	})
}

func bigHex(n *big.Int) string { return n.Text(16) }

// NewMTLSServer returns the mTLS http.Server. Serve it with ServeTLS("", "").
func (a *App) NewMTLSServer(addr string) *http.Server {
	s := newHTTPServer(addr, a.MTLSHandler())
	s.TLSConfig = a.TLSConfig()
	return s
}

// NewStatusServer returns the plain HTTP status http.Server.
func (a *App) NewStatusServer(addr string) *http.Server {
	return newHTTPServer(addr, a.StatusHandler())
}

func newHTTPServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16384,
	}
}

// Run starts the server subcommand and blocks until ctx is done.
func Run(ctx context.Context, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}
	cfg, err := ConfigFromEnv()
	if err != nil {
		return err
	}
	src, err := identity.New(identity.Config{
		LabCA:           &labcaapi.Client{BaseURL: cfg.LabCAURL},
		TokenFile:       cfg.TokenFile,
		TrustBundleFile: cfg.TrustBundleFile,
		Logger:          logger,
	})
	if err != nil {
		return err
	}
	fetcher := crl.New(crl.Config{
		URL:     cfg.CRLURL,
		Refresh: cfg.CRLRefresh,
		Issuer:  src.IssuingCA,
		Logger:  logger,
	})
	app := NewApp(src, fetcher, cfg.AllowedClientIDs, cfg.StatusDir, nil, logger)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errCh := make(chan error, 3)
	go func() {
		if err := src.Start(ctx); err != nil && ctx.Err() == nil {
			errCh <- fmt.Errorf("identity: %w", err)
		}
	}()
	go fetcher.Start(ctx)

	mtlsSrv := app.NewMTLSServer(cfg.MTLSAddr)
	statusSrv := app.NewStatusServer(cfg.StatusAddr)
	go func() { errCh <- fmt.Errorf("mtls listener: %w", mtlsSrv.ListenAndServeTLS("", "")) }()
	go func() { errCh <- fmt.Errorf("status listener: %w", statusSrv.ListenAndServe()) }()
	logger.Info("server started", "mtls_addr", cfg.MTLSAddr, "status_addr", cfg.StatusAddr)

	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-errCh:
	}
	cancel()
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutCancel()
	_ = mtlsSrv.Shutdown(shutCtx)
	_ = statusSrv.Shutdown(shutCtx)
	if runErr != nil && !errors.Is(runErr, http.ErrServerClosed) {
		return runErr
	}
	return nil
}

func resultsPath(dir string) string { return filepath.Join(dir, "results.json") }
