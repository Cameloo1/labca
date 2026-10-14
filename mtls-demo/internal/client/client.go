// Package client implements the demo-client subcommand: it calls the
// demo-server over mTLS on an interval and checks the server's SPIFFE ID.
package client

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/Cameloo1/labca/mtls-demo/internal/identity"
	"github.com/Cameloo1/labca/mtls-demo/internal/labcaapi"
	"github.com/Cameloo1/labca/mtls-demo/internal/spiffe"
)

// Config is the client's environment-derived configuration.
type Config struct {
	LabCAURL         string
	TokenFile        string
	TrustBundleFile  string
	ServerURL        string
	ExpectedServerID string
	Interval         time.Duration
	HealthAddr       string
}

// Result is the outcome of one call.
type Result struct {
	Status   int
	ServerID string
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
		LabCAURL:         getenv("LABCA_URL", "http://labca.labca-system.svc.cluster.local:8000"),
		TokenFile:        getenv("TOKEN_FILE", "/var/run/secrets/labca/token"),
		TrustBundleFile:  getenv("TRUST_BUNDLE_FILE", "/etc/labca/trust/trust-bundle.pem"),
		ServerURL:        getenv("SERVER_URL", "https://demo-server.mtls-demo.svc.cluster.local:8443/v1/ping"),
		ExpectedServerID: os.Getenv("EXPECTED_SERVER_ID"),
		HealthAddr:       getenv("HEALTH_ADDR", ":8081"),
	}
	if c.ExpectedServerID == "" {
		return Config{}, errors.New("EXPECTED_SERVER_ID is required")
	}
	if _, err := spiffe.Parse(c.ExpectedServerID); err != nil {
		return Config{}, fmt.Errorf("EXPECTED_SERVER_ID: %w", err)
	}
	d, err := time.ParseDuration(getenv("INTERVAL", "15s"))
	if err != nil || d <= 0 {
		return Config{}, errors.New("INTERVAL is not a positive duration")
	}
	c.Interval = d
	if _, err := url.Parse(c.ServerURL); err != nil {
		return Config{}, fmt.Errorf("SERVER_URL: %w", err)
	}
	return c, nil
}

// DialFunc overrides how the TCP connection is made (tests map service names to loopback).
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// CallOnce performs one authenticated GET against serverURL using a fresh
// transport, so each call performs a new handshake with the current certificate.
func CallOnce(ctx context.Context, src *identity.Source, serverURL, expectedServerID string, dial DialFunc) (Result, error) {
	u, err := url.Parse(serverURL)
	if err != nil {
		return Result{}, err
	}
	tr := &http.Transport{
		DialContext:       dial,
		DisableKeepAlives: true,
		TLSClientConfig: &tls.Config{
			MinVersion:           tls.VersionTLS13,
			RootCAs:              src.Roots(),
			GetClientCertificate: src.GetClientCertificate,
			ServerName:           u.Hostname(),
			VerifyConnection: func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) == 0 {
					return errors.New("server presented no certificate")
				}
				id, err := spiffe.FromCertificate(cs.PeerCertificates[0])
				if err != nil {
					return fmt.Errorf("server identity: %w", err)
				}
				if id != expectedServerID {
					return fmt.Errorf("server identity %q does not match expected %q", id, expectedServerID)
				}
				return nil
			},
		},
	}
	defer tr.CloseIdleConnections()
	hc := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, serverURL, nil)
	if err != nil {
		return Result{}, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return Result{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Result{Status: resp.StatusCode}, err
	}
	res := Result{Status: resp.StatusCode}
	var pong struct {
		ServerID string `json:"server_id"`
	}
	_ = json.Unmarshal(body, &pong)
	res.ServerID = pong.ServerID
	if resp.StatusCode != http.StatusOK {
		return res, fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
	}
	return res, nil
}

// HealthHandler answers /healthz: 200 when the identity is ready, else 503.
func HealthHandler(src *identity.Source) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if src.Ready() {
			_, _ = w.Write([]byte("ok"))
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("identity not ready"))
	})
	return mux
}

// Run starts the client subcommand and blocks until ctx is done.
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
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errCh := make(chan error, 2)
	go func() {
		if err := src.Start(ctx); err != nil && ctx.Err() == nil {
			errCh <- fmt.Errorf("identity: %w", err)
		}
	}()
	health := &http.Server{
		Addr:              cfg.HealthAddr,
		Handler:           HealthHandler(src),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16384,
	}
	go func() { errCh <- fmt.Errorf("health listener: %w", health.ListenAndServe()) }()

	var runErr error
loop:
	for {
		if src.Ready() {
			res, err := CallOnce(ctx, src, cfg.ServerURL, cfg.ExpectedServerID, nil)
			if err != nil {
				logger.Warn("call", "outcome", "error", "error", err.Error())
			} else {
				logger.Info("call", "outcome", "ok", "status", res.Status, "server_id", res.ServerID)
			}
		} else {
			logger.Info("call", "outcome", "waiting for identity")
		}
		select {
		case <-ctx.Done():
			break loop
		case runErr = <-errCh:
			break loop
		case <-time.After(cfg.Interval):
		}
	}
	cancel()
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutCancel()
	_ = health.Shutdown(shutCtx)
	if runErr != nil && !errors.Is(runErr, http.ErrServerClosed) {
		return runErr
	}
	return nil
}
