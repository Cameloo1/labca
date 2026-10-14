// Package labcaapi is an HTTP client for the LabCA workload API.
package labcaapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const maxBody = 1 << 20

// Client talks to LabCA.
type Client struct {
	BaseURL string
	HTTP    *http.Client
}

// SignResponse is the 201 body of the sign route.
type SignResponse struct {
	SPIFFEID       string `json:"spiffe_id"`
	SerialHex      string `json:"serial_hex"`
	NotBefore      string `json:"not_before"`
	NotAfter       string `json:"not_after"`
	CertificatePEM string `json:"certificate_pem"`
	ChainPEM       string `json:"chain_pem"`
	TrustBundlePEM string `json:"trust_bundle_pem"`
}

// RevokeResponse is the 200 body of the revoke route.
type RevokeResponse struct {
	Revoked   bool  `json:"revoked"`
	CRLNumber int64 `json:"crl_number"`
}

// APIError is a non-success response from LabCA.
type APIError struct {
	Status     int
	Code       string
	Detail     string
	RetryAfter time.Duration
}

func (e *APIError) Error() string {
	return fmt.Sprintf("labca: HTTP %d %s: %s", e.Status, e.Code, e.Detail)
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 10 * time.Second}
}

func (c *Client) post(ctx context.Context, path, token string, body any, wantStatus int, out any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.BaseURL, "/")+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("labca request failed: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return fmt.Errorf("labca read body: %w", err)
	}
	if resp.StatusCode != wantStatus {
		ae := &APIError{Status: resp.StatusCode}
		var eb struct {
			Error       string  `json:"error"`
			Detail      string  `json:"detail"`
			RetryAfterS float64 `json:"retry_after_s"`
		}
		if json.Unmarshal(data, &eb) == nil {
			ae.Code, ae.Detail = eb.Error, eb.Detail
			ae.RetryAfter = time.Duration(eb.RetryAfterS * float64(time.Second))
		}
		return ae
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("labca decode response: %w", err)
	}
	return nil
}

// Sign submits a CSR and returns the issued certificate.
func (c *Client) Sign(ctx context.Context, token string, csrPEM []byte) (*SignResponse, error) {
	var out SignResponse
	err := c.post(ctx, "/api/v1/workload/sign", token, map[string]string{"csr_pem": string(csrPEM)}, http.StatusCreated, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// Revoke revokes a certificate owned by the caller.
func (c *Client) Revoke(ctx context.Context, token, serialHex, reason string) (*RevokeResponse, error) {
	var out RevokeResponse
	err := c.post(ctx, "/api/v1/workload/revoke", token, map[string]string{"serial_hex": serialHex, "reason": reason}, http.StatusOK, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}
