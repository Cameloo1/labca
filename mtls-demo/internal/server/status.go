package server

import (
	"encoding/json"
	"html/template"
	"net/http"
	"os"
	"time"
)

type scenarioDoc struct {
	Name       string `json:"name"`
	Passed     bool   `json:"passed"`
	Expected   string `json:"expected"`
	Observed   string `json:"observed"`
	DurationMS int64  `json:"duration_ms"`
}

type verifierDoc struct {
	RunAt     string        `json:"run_at"`
	AllPassed bool          `json:"all_passed"`
	Scenarios []scenarioDoc `json:"scenarios"`
}

type serverDoc struct {
	SPIFFEID  string  `json:"spiffe_id"`
	SerialHex string  `json:"serial_hex"`
	NotAfter  *string `json:"not_after"`
	Renewals  int     `json:"renewals"`
}

type crlDoc struct {
	Number       int64   `json:"number"`
	ThisUpdate   *string `json:"this_update"`
	NextUpdate   *string `json:"next_update"`
	FetchedAt    *string `json:"fetched_at"`
	RevokedCount int     `json:"revoked_count"`
}

type statusDoc struct {
	GeneratedAt        string       `json:"generated_at"`
	Server             serverDoc    `json:"server"`
	CRL                crlDoc       `json:"crl"`
	LastAuthorizedCall *lastCall    `json:"last_authorized_call"`
	Verifier           *verifierDoc `json:"verifier"`
}

func timePtr(t time.Time) *string {
	if t.IsZero() {
		return nil
	}
	s := t.UTC().Format(time.RFC3339)
	return &s
}

func (a *App) readVerifier() *verifierDoc {
	raw, err := os.ReadFile(resultsPath(a.statusDir))
	if err != nil || len(raw) == 0 {
		return nil
	}
	var v verifierDoc
	if json.Unmarshal(raw, &v) != nil || v.RunAt == "" {
		return nil
	}
	if v.Scenarios == nil {
		v.Scenarios = []scenarioDoc{}
	}
	return &v
}

func (a *App) buildStatus() statusDoc {
	cur := a.src.Current()
	st := a.fetcher.Status()
	return statusDoc{
		GeneratedAt: a.clock.Now().UTC().Format(time.RFC3339),
		Server: serverDoc{
			SPIFFEID:  cur.SPIFFEID,
			SerialHex: cur.SerialHex,
			NotAfter:  timePtr(cur.NotAfter),
			Renewals:  cur.Renewals,
		},
		CRL: crlDoc{
			Number:       st.Number,
			ThisUpdate:   timePtr(st.ThisUpdate),
			NextUpdate:   timePtr(st.NextUpdate),
			FetchedAt:    timePtr(st.FetchedAt),
			RevokedCount: st.RevokedCount,
		},
		LastAuthorizedCall: a.last.Load(),
		Verifier:           a.readVerifier(),
	}
}

type pageData struct {
	Doc        statusDoc
	AgeMinutes int
	HasAge     bool
}

var pageTmpl = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="30">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>mtls-demo status</title>
<style>
body{font-family:system-ui,sans-serif;margin:2rem auto;max-width:60rem;padding:0 1rem;color:#111;background:#fff}
table{border-collapse:collapse;width:100%}
th,td{border:1px solid #ccc;padding:.4rem .6rem;text-align:left;vertical-align:top}
.pass{color:#0a6b2d;font-weight:bold}
.fail{color:#a30000;font-weight:bold}
code{word-break:break-all}
</style>
</head>
<body>
<h1>mtls-demo status</h1>
<p>Generated at {{.Doc.GeneratedAt}}</p>

<h2>Adversarial verifier</h2>
{{with .Doc.Verifier}}
<p>Overall: {{if .AllPassed}}<span class="pass">all scenarios passed</span>{{else}}<span class="fail">at least one scenario failed</span>{{end}}</p>
<p>Run at {{.RunAt}}{{if $.HasAge}} ({{$.AgeMinutes}} minutes ago){{end}}</p>
<table>
<thead><tr><th>Scenario</th><th>Passed</th><th>Expected</th><th>Observed</th><th>Duration (ms)</th></tr></thead>
<tbody>
{{range .Scenarios}}<tr><td>{{.Name}}</td><td>{{if .Passed}}<span class="pass">pass</span>{{else}}<span class="fail">fail</span>{{end}}</td><td>{{.Expected}}</td><td>{{.Observed}}</td><td>{{.DurationMS}}</td></tr>
{{end}}</tbody>
</table>
{{else}}
<p>No verifier results yet.</p>
{{end}}

<h2>Server identity</h2>
<table>
<tr><th>SPIFFE ID</th><td><code>{{.Doc.Server.SPIFFEID}}</code></td></tr>
<tr><th>Serial</th><td><code>{{.Doc.Server.SerialHex}}</code></td></tr>
<tr><th>Not after</th><td>{{if .Doc.Server.NotAfter}}{{.Doc.Server.NotAfter}}{{else}}not issued yet{{end}}</td></tr>
<tr><th>Renewals</th><td>{{.Doc.Server.Renewals}}</td></tr>
</table>

<h2>Certificate revocation list</h2>
<table>
<tr><th>Number</th><td>{{.Doc.CRL.Number}}</td></tr>
<tr><th>This update</th><td>{{if .Doc.CRL.ThisUpdate}}{{.Doc.CRL.ThisUpdate}}{{else}}none{{end}}</td></tr>
<tr><th>Next update</th><td>{{if .Doc.CRL.NextUpdate}}{{.Doc.CRL.NextUpdate}}{{else}}none{{end}}</td></tr>
<tr><th>Revoked entries</th><td>{{.Doc.CRL.RevokedCount}}</td></tr>
</table>

<h2>Last authorized call</h2>
{{with .Doc.LastAuthorizedCall}}
<table>
<tr><th>Client ID</th><td><code>{{.ClientID}}</code></td></tr>
<tr><th>Client serial</th><td><code>{{.ClientSerialHex}}</code></td></tr>
<tr><th>At</th><td>{{.At}}</td></tr>
</table>
{{else}}
<p>No authorized call yet.</p>
{{end}}
</body>
</html>
`))

func setSecurityHeaders(h http.Header) {
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
}

func notFound(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte("not found\n"))
}

// StatusHandler serves the plain HTTP status routes.
func (a *App) StatusHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w.Header())
		if r.Method != http.MethodGet {
			notFound(w)
			return
		}
		switch r.URL.Path {
		case "/status.json":
			w.Header().Set("Cache-Control", "no-store")
			writeJSON(w, http.StatusOK, a.buildStatus())
		case "/":
			a.servePage(w)
		case "/healthz":
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = w.Write([]byte("ok"))
		case "/readyz":
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			switch {
			case !a.src.Ready():
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte("identity not ready"))
			case !a.fetcher.Fresh():
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte("crl not fresh"))
			default:
				_, _ = w.Write([]byte("ready"))
			}
		default:
			notFound(w)
		}
	})
}

func (a *App) servePage(w http.ResponseWriter) {
	doc := a.buildStatus()
	pd := pageData{Doc: doc}
	if doc.Verifier != nil {
		if t, err := time.Parse(time.RFC3339, doc.Verifier.RunAt); err == nil {
			pd.HasAge = true
			pd.AgeMinutes = int(a.clock.Now().Sub(t) / time.Minute)
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := pageTmpl.Execute(w, pd); err != nil {
		a.logger.Error("render status page", "error", err.Error())
	}
}
