package api_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/wanaware/vulnframework/internal/api"
	"github.com/wanaware/vulnframework/internal/policy"
	"github.com/wanaware/vulnframework/internal/score"
	"github.com/wanaware/vulnframework/internal/store"
	"github.com/wanaware/vulnframework/internal/store/storetest"
)

type scanEnv struct {
	st  store.Store
	srv *httptest.Server
	log *api.MemoryAccessLog
	now time.Time
}

// scanBackends opens a migrated store per backend: memory always, Postgres
// when the test DSN is set.
func scanBackends(t *testing.T) map[string]func(t *testing.T) store.Store {
	out := map[string]func(t *testing.T) store.Store{
		"memory": func(t *testing.T) store.Store {
			s := store.NewMemory()
			if err := s.Migrate(context.Background()); err != nil {
				t.Fatal(err)
			}
			return s
		},
	}
	if os.Getenv(storetest.EnvDSN) != "" {
		out["postgres"] = func(t *testing.T) store.Store {
			s := store.NewPostgres(storetest.OpenDB(t, "api_scans"))
			ctx := context.Background()
			if err := s.MigrateTo(ctx, 0); err != nil {
				t.Fatal(err)
			}
			if err := s.Migrate(ctx); err != nil {
				t.Fatal(err)
			}
			return s
		}
	}
	return out
}

func newScanEnv(t *testing.T, s store.Store, enabled bool) *scanEnv {
	t.Helper()
	cal, err := score.LoadCalibration("../../config/calibration.yaml")
	if err != nil {
		t.Fatal(err)
	}
	pol, err := policy.LoadConfig("../../config/policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	env := &scanEnv{st: s, log: &api.MemoryAccessLog{}, now: time.Date(2026, 10, 22, 10, 0, 0, 0, time.UTC)}
	srv, err := api.New(api.Config{
		Store: s, Calibration: cal, Policy: pol,
		Auth:      api.HeaderAuth{UserHeader: "X-Auth-User", LevelHeader: "X-Auth-Level", ReposHeader: "X-Auth-Repos"},
		AccessLog: env.log, ScanRequests: enabled, ScanRatePerMinute: 3,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Clock:  func() time.Time { return env.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	env.srv = httptest.NewServer(srv.Handler())
	t.Cleanup(env.srv.Close)
	ctx := context.Background()
	for _, r := range []store.Repo{{Name: "octo/api", Tier: 2}, {Name: "octo/web", Tier: 3}, {Name: "octo/old", Tier: 3, Archived: true}} {
		if err := s.UpsertRepo(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.SetExclusion(ctx, store.RepoExclusion{Name: "octo/old", Reason: "a vendored mirror", ExcludedBy: "pat", ExcludedAt: env.now}); err != nil {
		t.Fatal(err)
	}
	return env
}

type caller struct{ user, level string }

var (
	owner    = caller{"pat", "security_owner"}
	engineer = caller{"eng", "engineer"}
)

func (e *scanEnv) do(t *testing.T, method, path string, c caller, body string, hdr map[string]string) (int, map[string]any, []byte) {
	t.Helper()
	req, _ := http.NewRequest(method, e.srv.URL+path, strings.NewReader(body))
	req.Header.Set("X-Auth-User", c.user)
	req.Header.Set("X-Auth-Level", c.level)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return res.StatusCode, m, raw
}

func (e *scanEnv) csrf(t *testing.T, c caller) string {
	t.Helper()
	status, m, raw := e.do(t, http.MethodGet, "/v1/csrf", c, "", nil)
	if status != 200 {
		t.Fatalf("GET /v1/csrf = %d %s", status, raw)
	}
	return m["token"].(string)
}

func (e *scanEnv) write(t *testing.T, path string, c caller, body string) (int, map[string]any, []byte) {
	return e.do(t, http.MethodPost, path, c, body, map[string]string{
		"Sec-Fetch-Site": "same-origin", api.CSRFHeader: e.csrf(t, c), "Content-Type": "application/json",
	})
}

func TestScanRequestsFromTheInterface(t *testing.T) {
	for name, open := range scanBackends(t) {
		t.Run(name, func(t *testing.T) {
			e := newScanEnv(t, open(t), true)
			ctx := context.Background()

			// Queueing, then merging a duplicate.
			status, m, raw := e.write(t, "/v1/scans", owner, `{"repo":"octo/api"}`)
			if status != http.StatusCreated || m["merged"] != false {
				t.Fatalf("first request = %d %s", status, raw)
			}
			first := m["request"].(map[string]any)["id"].(string)
			status, m, raw = e.write(t, "/v1/scans", owner, `{"repo":"octo/api"}`)
			if status != http.StatusOK || m["merged"] != true || m["request"].(map[string]any)["id"] != first {
				t.Fatalf("duplicate = %d %s; want 200 merged into %s", status, raw, first)
			}

			// An excluded repository is refused with the reason, and the
			// refusal is kept as an audit row.
			status, m, raw = e.write(t, "/v1/scans", owner, `{"repo":"octo/old"}`)
			if status != http.StatusConflict || !strings.Contains(string(raw), "a vendored mirror") {
				t.Fatalf("excluded = %d %s", status, raw)
			}
			rows, _ := e.st.ScanRequests(ctx, store.ScanQuery{Repo: "octo/old"})
			if len(rows) != 1 || rows[0].Status != store.ScanRefused || rows[0].RequestedBy != "pat" {
				t.Errorf("refusal audit row: %+v", rows)
			}

			// An unregistered repository is not found; nothing is queued.
			if status, _, raw = e.write(t, "/v1/scans", owner, `{"repo":"octo/nope"}`); status != http.StatusNotFound {
				t.Errorf("unregistered = %d %s", status, raw)
			}

			// Rate limit: three rows this minute (queued, refused, and the
			// next) and the fourth request is refused.
			if status, _, raw = e.write(t, "/v1/scans", owner, `{"repo":"octo/web"}`); status != http.StatusCreated {
				t.Fatalf("octo/web = %d %s", status, raw)
			}
			if status, _, raw = e.write(t, "/v1/scans", owner, `{"repo":"octo/web"}`); status != http.StatusTooManyRequests {
				t.Errorf("over the rate = %d %s; want 429", status, raw)
			}
			e.now = e.now.Add(2 * time.Minute)

			// Scan all: one batch over the included repositories; both are
			// already queued, so both merge.
			status, m, raw = e.write(t, "/v1/scans/all", owner, "")
			if status != http.StatusCreated || m["merged"].(float64) != 2 || m["queued"].(float64) != 0 {
				t.Errorf("scan all = %d %s", status, raw)
			}

			// The list, and the access log's record of what each write did.
			status, _, raw = e.do(t, http.MethodGet, "/v1/scans?repo=octo/api", owner, "", nil)
			if status != 200 || !strings.Contains(string(raw), first) {
				t.Errorf("list = %d %s", status, raw)
			}
			var subjects []string
			for _, ev := range e.log.Events() {
				if ev.Method == http.MethodPost {
					subjects = append(subjects, ev.Principal+" "+ev.Subject)
				}
			}
			joined := strings.Join(subjects, "\n")
			for _, want := range []string{"pat repo=octo/api queued", "pat repo=octo/api merged into " + first,
				"pat repo=octo/old refused: excluded by pat", "pat repo=octo/nope refused: not registered", "pat all included repositories"} {
				if !strings.Contains(joined, want) {
					t.Errorf("access log lacks %q:\n%s", want, joined)
				}
			}
		})
	}
}

func TestScanRequestsAreRefusedWithoutEveryCheck(t *testing.T) {
	for name, open := range scanBackends(t) {
		t.Run(name, func(t *testing.T) {
			e := newScanEnv(t, open(t), true)
			body := `{"repo":"octo/api"}`
			token := e.csrf(t, owner)
			same := map[string]string{"Sec-Fetch-Site": "same-origin", api.CSRFHeader: token}

			cases := []struct {
				name string
				c    caller
				hdr  map[string]string
				body string
				want int
			}{
				{"engineer level", engineer, map[string]string{"Sec-Fetch-Site": "same-origin", api.CSRFHeader: e.csrf(t, engineer)}, body, 403},
				{"no CSRF token", owner, map[string]string{"Sec-Fetch-Site": "same-origin"}, body, 403},
				{"forged CSRF token", owner, map[string]string{"Sec-Fetch-Site": "same-origin", api.CSRFHeader: "AAAA"}, body, 403},
				{"another person's token", owner, map[string]string{"Sec-Fetch-Site": "same-origin", api.CSRFHeader: e.csrf(t, engineer)}, body, 403},
				{"cross-site", owner, map[string]string{"Sec-Fetch-Site": "cross-site", api.CSRFHeader: token}, body, 403},
				{"same-site subdomain", owner, map[string]string{"Sec-Fetch-Site": "same-site", api.CSRFHeader: token}, body, 403},
				{"foreign Origin", owner, map[string]string{"Origin": "https://evil.example", api.CSRFHeader: token}, body, 403},
				{"no origin headers at all", owner, map[string]string{api.CSRFHeader: token}, body, 403},
				{"unknown field", owner, same, `{"repo":"octo/api","branch":"main"}`, 400},
				{"two values", owner, same, `{"repo":"octo/api"}{"repo":"octo/web"}`, 400},
				{"path in name", owner, same, `{"repo":"../etc/passwd"}`, 400},
				{"body on scan all", owner, same, `{"repo":"octo/api"}`, 400},
			}
			for _, c := range cases {
				path := "/v1/scans"
				if c.name == "body on scan all" {
					path = "/v1/scans/all"
				}
				status, _, raw := e.do(t, http.MethodPost, path, c.c, c.body, c.hdr)
				if status != c.want {
					t.Errorf("%s: %d %s; want %d", c.name, status, raw, c.want)
				}
			}
			if rows, _ := e.st.ScanRequests(context.Background(), store.ScanQuery{}); len(rows) != 0 {
				t.Errorf("refused requests queued %d scans", len(rows))
			}

			// An Origin matching the server is accepted from a browser that
			// sends no Sec-Fetch-Site.
			status, _, raw := e.do(t, http.MethodPost, "/v1/scans", owner, body,
				map[string]string{"Origin": e.srv.URL, api.CSRFHeader: token})
			if status != http.StatusCreated {
				t.Errorf("own Origin = %d %s; want 201", status, raw)
			}
		})
	}
}

func TestScanRequestsAreOffInTheDemonstration(t *testing.T) {
	e := newScanEnv(t, store.NewMemory(), false)
	_ = e.st.Migrate(context.Background())
	status, _, raw := e.write(t, "/v1/scans", owner, `{"repo":"octo/api"}`)
	if status != http.StatusServiceUnavailable {
		t.Errorf("with scan requests off = %d %s; want 503", status, raw)
	}
	_, m, _ := e.do(t, http.MethodGet, "/v1/health", owner, "", nil)
	if m["scan_requests"] != false {
		t.Errorf("health scan_requests = %v; want false", m["scan_requests"])
	}
}
