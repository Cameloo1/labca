// Package fakelabca is an in-process stand-in for the LabCA workload API and
// CRL endpoint. It exists for tests and makes no outbound network calls.
package fakelabca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"time"
)

type workload struct{ NS, SA string }

type revokedEntry struct {
	serial *big.Int
	at     time.Time
}

// Server is a fake LabCA.
type Server struct {
	*httptest.Server

	mu          sync.Mutex
	trustDomain string
	rootCert    *x509.Certificate
	rootPEM     []byte
	rootKey     *ecdsa.PrivateKey
	issCert     *x509.Certificate
	issKey      *ecdsa.PrivateKey
	tokens      map[string]workload
	seen        []string
	owners      map[string]string // serial hex -> spiffe id
	revoked     []revokedEntry
	crlNumber   int64
	nextUpdate  time.Time
	crlDER      []byte
	validity    time.Duration
	failNext    []int
	now         func() time.Time
}

// SetNow replaces the time source used for certificate and CRL times.
func (s *Server) SetNow(f func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.now = f
}

// New starts a fake LabCA for the given trust domain.
func New(trustDomain string) *Server {
	s := &Server{
		trustDomain: trustDomain,
		tokens:      map[string]workload{},
		owners:      map[string]string{},
		crlNumber:   1,
		validity:    time.Hour,
		now:         time.Now,
	}
	s.nextUpdate = time.Now().Add(24 * time.Hour)
	rootKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	must(err)
	now := time.Now()
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Fake Root CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour * 365),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            1,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	must(err)
	s.rootCert, err = x509.ParseCertificate(der)
	must(err)
	s.rootKey = rootKey
	s.rootPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	s.issKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	issTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Fake Issuing CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour * 365),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err = x509.CreateCertificate(rand.Reader, issTmpl, s.rootCert, &s.issKey.PublicKey, rootKey)
	must(err)
	s.issCert, err = x509.ParseCertificate(der)
	must(err)
	s.regenCRLLocked()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/workload/sign", s.handleSign)
	mux.HandleFunc("/api/v1/workload/revoke", s.handleRevoke)
	mux.HandleFunc("/pki/issuing/crl.der", s.handleCRL)
	s.Server = httptest.NewServer(mux)
	return s
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

// AddToken maps a bearer token to a namespace and service account.
func (s *Server) AddToken(token, ns, sa string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[token] = workload{ns, sa}
}

// RootPEM returns the root certificate in PEM form (the trust bundle).
func (s *Server) RootPEM() []byte { return append([]byte(nil), s.rootPEM...) }

// IssuingCA returns the issuing CA certificate.
func (s *Server) IssuingCA() *x509.Certificate { return s.issCert }

// CRLNumber returns the current CRL number.
func (s *Server) CRLNumber() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.crlNumber
}

// SetCRLNumber forces the CRL number and regenerates the CRL (rollback tests).
func (s *Server) SetCRLNumber(n int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.crlNumber = n
	s.regenCRLLocked()
}

// SetNextUpdate sets the nextUpdate of the served CRL and regenerates it.
func (s *Server) SetNextUpdate(t time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextUpdate = t
	s.regenCRLLocked()
}

// SetValidity sets the lifetime of certificates issued from now on.
func (s *Server) SetValidity(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.validity = d
}

// FailNext makes the next sign request return the given HTTP status.
func (s *Server) FailNext(status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failNext = append(s.failNext, status)
}

// Tokens returns every bearer token received by the sign and revoke routes.
func (s *Server) Tokens() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.seen...)
}

// RevokeSerial adds a serial to the CRL directly (bypassing ownership checks).
func (s *Server) RevokeSerial(serialHex string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revokeLocked(serialHex)
}

// CRLDER returns the current DER CRL.
func (s *Server) CRLDER() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.crlDER...)
}

func (s *Server) revokeLocked(serialHex string) {
	n, ok := new(big.Int).SetString(serialHex, 16)
	if !ok {
		return
	}
	s.revoked = append(s.revoked, revokedEntry{serial: n, at: s.now()})
	s.crlNumber++
	s.regenCRLLocked()
}

func (s *Server) regenCRLLocked() {
	tmpl := &x509.RevocationList{
		Number:     big.NewInt(s.crlNumber),
		ThisUpdate: s.now().Add(-time.Second),
		NextUpdate: s.nextUpdate,
	}
	for _, r := range s.revoked {
		tmpl.RevokedCertificateEntries = append(tmpl.RevokedCertificateEntries, x509.RevocationListEntry{
			SerialNumber:   r.serial,
			RevocationTime: r.at,
		})
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, s.issCert, s.issKey)
	must(err)
	s.crlDER = der
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func apiErr(w http.ResponseWriter, status int, code, detail string) {
	writeJSON(w, status, map[string]any{"error": code, "detail": detail})
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if t, ok := strings.CutPrefix(h, "Bearer "); ok {
		return t
	}
	return ""
}

func codeFor(status int) string {
	switch status {
	case 400:
		return "invalid_csr"
	case 401:
		return "unauthenticated"
	case 403:
		return "not_allowlisted"
	case 429:
		return "rate_limited"
	default:
		return "issuer_unavailable"
	}
}

func (s *Server) handleSign(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		apiErr(w, 405, "method_not_allowed", "POST only")
		return
	}
	token := bearer(r)
	s.mu.Lock()
	s.seen = append(s.seen, token)
	if len(s.failNext) > 0 {
		st := s.failNext[0]
		s.failNext = s.failNext[1:]
		s.mu.Unlock()
		apiErr(w, st, codeFor(st), "injected failure")
		return
	}
	wl, ok := s.tokens[token]
	validity := s.validity
	issueNow := s.now()
	s.mu.Unlock()
	if !ok {
		apiErr(w, 401, "unauthenticated", "unknown token")
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var req struct {
		CSRPEM string `json:"csr_pem"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		apiErr(w, 400, "invalid_csr", "bad JSON")
		return
	}
	blk, _ := pem.Decode([]byte(req.CSRPEM))
	if blk == nil {
		apiErr(w, 400, "invalid_csr", "no PEM block")
		return
	}
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		apiErr(w, 400, "invalid_csr", "bad CSR")
		return
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	must(err)
	serial.Add(serial, big.NewInt(1000))
	id := "spiffe://" + s.trustDomain + "/ns/" + wl.NS + "/sa/" + wl.SA
	u, _ := url.Parse(id)
	now := issueNow.UTC().Truncate(time.Second)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: wl.SA},
		NotBefore:    now,
		NotAfter:     now.Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{u},
		DNSNames:     []string{wl.SA + "." + wl.NS + ".svc", wl.SA + "." + wl.NS + ".svc.cluster.local"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, s.issCert, csr.PublicKey, s.issKey)
	if err != nil {
		apiErr(w, 400, "invalid_csr", "unsupported public key")
		return
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	issPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.issCert.Raw})
	serialHex := serial.Text(16)
	s.mu.Lock()
	s.owners[serialHex] = id
	s.mu.Unlock()
	writeJSON(w, 201, map[string]string{
		"spiffe_id":        id,
		"serial_hex":       serialHex,
		"not_before":       tmpl.NotBefore.UTC().Format(time.RFC3339),
		"not_after":        tmpl.NotAfter.UTC().Format(time.RFC3339),
		"certificate_pem":  string(leafPEM),
		"chain_pem":        string(leafPEM) + string(issPEM),
		"trust_bundle_pem": string(s.rootPEM),
	})
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		apiErr(w, 405, "method_not_allowed", "POST only")
		return
	}
	token := bearer(r)
	s.mu.Lock()
	s.seen = append(s.seen, token)
	wl, ok := s.tokens[token]
	s.mu.Unlock()
	if !ok {
		apiErr(w, 401, "unauthenticated", "unknown token")
		return
	}
	var req struct {
		SerialHex string `json:"serial_hex"`
		Reason    string `json:"reason"`
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err := json.Unmarshal(body, &req); err != nil {
		apiErr(w, 400, "invalid_request", "bad JSON")
		return
	}
	id := "spiffe://" + s.trustDomain + "/ns/" + wl.NS + "/sa/" + wl.SA
	s.mu.Lock()
	owner, known := s.owners[req.SerialHex]
	if !known {
		s.mu.Unlock()
		apiErr(w, 404, "not_found", "unknown serial")
		return
	}
	if owner != id {
		s.mu.Unlock()
		apiErr(w, 403, "not_owner", "certificate belongs to another identity")
		return
	}
	s.revokeLocked(req.SerialHex)
	n := s.crlNumber
	s.mu.Unlock()
	writeJSON(w, 200, map[string]any{"revoked": true, "crl_number": n})
}

func (s *Server) handleCRL(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	der := s.crlDER
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/pkix-crl")
	_, _ = w.Write(der)
}

// NewSiblingIssuer creates a second issuing CA signed by the same root. Its
// certificates chain to the trust bundle but are not covered by the served CRL.
func (s *Server) NewSiblingIssuer() (*x509.Certificate, *ecdsa.PrivateKey) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "Fake Issuing CA 2"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour * 365),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, s.rootCert, &key.PublicKey, s.rootKey)
	must(err)
	cert, err := x509.ParseCertificate(der)
	must(err)
	return cert, key
}

// IssueLeaf issues a client and server auth leaf with the given SPIFFE ID
// URI SAN and a fresh P-256 key. The chain is [leaf, issuer].
func IssueLeaf(issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey, spiffeID string, validity time.Duration) (*tls.Certificate, error) {
	u, err := url.Parse(spiffeID)
	if err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		return nil, err
	}
	serial.Add(serial, big.NewInt(1000))
	now := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    now,
		NotAfter:     now.Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{u},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, &key.PublicKey, issuerKey)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der, issuer.Raw}, PrivateKey: key, Leaf: leaf}, nil
}
