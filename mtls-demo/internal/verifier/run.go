package verifier

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Cameloo1/labca/mtls-demo/internal/identity"
	"github.com/Cameloo1/labca/mtls-demo/internal/labcaapi"
	"github.com/Cameloo1/labca/mtls-demo/internal/spiffe"
)

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func durationEnv(k, def string) (time.Duration, error) {
	d, err := time.ParseDuration(getenv(k, def))
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%s is not a positive duration", k)
	}
	return d, nil
}

// ConfigFromEnv reads and validates the environment.
func ConfigFromEnv() (Config, error) {
	c := Config{
		LabCAURL:         getenv("LABCA_URL", "http://labca.labca-system.svc.cluster.local:8000"),
		TokenFile:        getenv("TOKEN_FILE", "/var/run/secrets/labca/token"),
		TrustBundleFile:  getenv("TRUST_BUNDLE_FILE", "/etc/labca/trust/trust-bundle.pem"),
		ServerURL:        getenv("SERVER_URL", "https://demo-server.mtls-demo.svc.cluster.local:8443/v1/ping"),
		ServerStatusURL:  getenv("SERVER_STATUS_URL", "http://demo-server.mtls-demo.svc.cluster.local:8080/status.json"),
		DemoClientID:     os.Getenv("DEMO_CLIENT_ID"),
		ExpectedServerID: os.Getenv("EXPECTED_SERVER_ID"),
		KubeTokenFile:    getenv("KUBE_TOKEN_FILE", "/var/run/secrets/kube-api/token"),
		KubeCAFile:       getenv("KUBE_CA_FILE", "/var/run/secrets/kube-api/ca.crt"),
		PodNamespace:     os.Getenv("POD_NAMESPACE"),
		StatusConfigMap:  getenv("STATUS_CONFIGMAP", "mtls-status"),
	}
	for _, f := range []struct{ name, val string }{
		{"DEMO_CLIENT_ID", c.DemoClientID},
		{"EXPECTED_SERVER_ID", c.ExpectedServerID},
	} {
		if f.val == "" {
			return Config{}, fmt.Errorf("%s is required", f.name)
		}
		if _, err := spiffe.Parse(f.val); err != nil {
			return Config{}, fmt.Errorf("%s: %w", f.name, err)
		}
	}
	if c.PodNamespace == "" {
		return Config{}, errors.New("POD_NAMESPACE is required")
	}
	var err error
	if c.AuthorizedCallMaxAge, err = durationEnv("AUTHORIZED_CALL_MAX_AGE", "120s"); err != nil {
		return Config{}, err
	}
	if c.RevokeWaitTimeout, err = durationEnv("REVOKE_WAIT_TIMEOUT", "120s"); err != nil {
		return Config{}, err
	}
	if c.RevokePollInterval, err = durationEnv("REVOKE_POLL_INTERVAL", "2s"); err != nil {
		return Config{}, err
	}
	c.KubeAPIURL = os.Getenv("KUBE_API_URL")
	if c.KubeAPIURL == "" {
		host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
		if host == "" || port == "" {
			return Config{}, errors.New("KUBE_API_URL is not set and KUBERNETES_SERVICE_HOST/PORT are missing")
		}
		c.KubeAPIURL = "https://" + host + ":" + port
	}
	return c, nil
}

func kubeHTTPClient(caFile string) (*http.Client, error) {
	ca, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read kube CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("kube CA file has no certificates")
	}
	return &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}},
	}, nil
}

// WriteConfigMap merge-patches the results into the status ConfigMap.
func WriteConfigMap(ctx context.Context, cfg Config, res Results) error {
	hc, err := kubeHTTPClient(cfg.KubeCAFile)
	if err != nil {
		return err
	}
	tokenRaw, err := os.ReadFile(cfg.KubeTokenFile)
	if err != nil {
		return fmt.Errorf("read kube token: %w", err)
	}
	token := strings.TrimSpace(string(tokenRaw))
	resJSON, err := json.Marshal(res)
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string]any{"data": map[string]string{"results.json": string(resJSON)}})
	if err != nil {
		return err
	}
	u := strings.TrimRight(cfg.KubeAPIURL, "/") + "/api/v1/namespaces/" + cfg.PodNamespace + "/configmaps/" + cfg.StatusConfigMap
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/merge-patch+json")
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("configmap patch: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("configmap patch: HTTP %d", resp.StatusCode)
	}
	return nil
}

// Run executes the verifier subcommand once.
func Run(ctx context.Context, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}
	cfg, err := ConfigFromEnv()
	if err != nil {
		return err
	}
	labca := &labcaapi.Client{BaseURL: cfg.LabCAURL}
	src, err := identity.New(identity.Config{
		LabCA:           labca,
		TokenFile:       cfg.TokenFile,
		TrustBundleFile: cfg.TrustBundleFile,
		Logger:          logger,
	})
	if err != nil {
		return err
	}
	startCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	idCtx, idCancel := context.WithTimeout(startCtx, 2*time.Minute)
	defer idCancel()
	if err := src.Start(idCtx); err != nil {
		return fmt.Errorf("verifier identity: %w", err)
	}
	v := &Verifier{Cfg: cfg, Src: src, LabCA: labca}
	res := v.RunAll(ctx)
	out, err := json.Marshal(res)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, string(out))
	writeErr := WriteConfigMap(ctx, cfg, res)
	if writeErr != nil {
		logger.Error("configmap write failed", "error", writeErr.Error())
	}
	if !res.AllPassed {
		return errors.New("one or more scenarios failed")
	}
	if writeErr != nil {
		return writeErr
	}
	return nil
}
