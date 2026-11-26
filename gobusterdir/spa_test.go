package gobusterdir

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OJ/gobuster/v3/libgobuster"
)

type spaAcceptanceCase struct {
	name     string
	server   func(*testing.T) *httptest.Server
	words    []string
	expected []string
}

func TestSPASoft404Acceptance(t *testing.T) {
	tests := []spaAcceptanceCase{
		staticSPAFixture(),
		echoPathSPAFixture(),
		dynamicSPAFixture(),
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := test.server(t)
			defer server.Close()

			actual := scanFixture(t, server.URL, test.words)
			if strings.Join(actual, ",") != strings.Join(test.expected, ",") {
				t.Fatalf("valid paths mismatch\nwant: %v\ngot:  %v", test.expected, actual)
			}
		})
	}
}

func scanFixture(t *testing.T, rawURL string, words []string) []string {
	t.Helper()

	opts := fixtureOptions(t, rawURL)
	return scanWithOptions(t, opts, words)
}

func fixtureOptions(t *testing.T, rawURL string) *OptionsDir {
	t.Helper()

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("could not parse URL: %v", err)
	}

	opts := NewOptions()
	opts.URL = parsedURL
	opts.Timeout = 5 * time.Second
	opts.StatusCodes = "200"
	opts.StatusCodesParsed, err = libgobuster.ParseCommaSeparatedInt(opts.StatusCodes)
	if err != nil {
		t.Fatalf("could not parse status codes: %v", err)
	}

	return opts
}

func scanWithOptions(t *testing.T, opts *OptionsDir, words []string) []string {
	t.Helper()

	globalOpts := &libgobuster.Options{Threads: 1}
	plugin, err := New(globalOpts, opts, libgobuster.NewLogger(false))
	if err != nil {
		t.Fatalf("could not create plugin: %v", err)
	}

	progress := libgobuster.NewProgress()
	if err := plugin.PreRun(t.Context(), progress); err != nil {
		t.Fatalf("PreRun failed: %v", err)
	}

	actual := make([]string, 0, len(words))
	for _, word := range words {
		result, err := plugin.ProcessWord(t.Context(), word, progress)
		if err != nil {
			t.Fatalf("ProcessWord(%q) failed: %v", word, err)
		}
		if result == nil {
			continue
		}
		resultDir, ok := result.(Result)
		if !ok {
			t.Fatalf("unexpected result type %T", result)
		}
		actual = append(actual, strings.TrimSpace(resultDir.Path))
	}

	sort.Strings(actual)
	return actual
}

func TestSPASoft404CompatibilityWithExistingModes(t *testing.T) {
	fallback := `<!doctype html><html><head><title>App</title></head><body><div id="root"></div></body></html>`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/", "/admin.html/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = fmt.Fprint(w, "<html><body><h1>Admin console</h1><p>Users, roles and audit events.</p></body></html>")
		default:
			w.Header().Set("Content-Type", "text/html")
			_, _ = fmt.Fprint(w, fallback)
		}
	}))
	defer server.Close()

	opts := fixtureOptions(t, server.URL)
	opts.UseSlash = true
	opts.Extensions = "html"
	opts.ExtensionsParsed, _ = libgobuster.ParseExtensions(opts.Extensions)

	actual := scanWithOptions(t, opts, []string{"admin", "admin.html", "missing", "missing.html", "admin", "missing"})
	expected := []string{"admin/", "admin.html/"}
	sort.Strings(expected)
	if strings.Join(actual, ",") != strings.Join(expected, ",") {
		t.Fatalf("compatibility result mismatch\nwant: %v\ngot:  %v", expected, actual)
	}
}

func TestSPASoft404ExcludeLengthStillWorks(t *testing.T) {
	fallback := strings.Repeat("spa-fallback-", 40)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/real" {
			_, _ = fmt.Fprint(w, "real result")
			return
		}
		_, _ = fmt.Fprint(w, fallback)
	}))
	defer server.Close()

	opts := fixtureOptions(t, server.URL)
	opts.Soft404Detection = false
	opts.ExcludeLength = fmt.Sprintf("%d", len(fallback))
	opts.ExcludeLengthParsed, _ = libgobuster.ParseCommaSeparatedInt(opts.ExcludeLength)

	actual := scanWithOptions(t, opts, []string{"real", "missing"})
	if strings.Join(actual, ",") != "real" {
		t.Fatalf("exclude-length result mismatch: %v", actual)
	}
}

func TestSPAResultDeduplicationAndClustering(t *testing.T) {
	fallback := `<!doctype html><html><head><title>App</title></head><body><div id="root"></div></body></html>`
	valid := `<!doctype html><html><head><title>Section</title></head><body><nav>Home Reports Settings</nav><main><h1>Section overview</h1><p>Shared section content.</p></main></body></html>`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin", "/admin.html", "/dashboard":
			w.Header().Set("Content-Type", "text/html")
			_, _ = fmt.Fprint(w, valid)
		default:
			w.Header().Set("Content-Type", "text/html")
			_, _ = fmt.Fprint(w, fallback)
		}
	}))
	defer server.Close()

	opts := fixtureOptions(t, server.URL)
	opts.Cluster = true
	opts.Extensions = "html"
	opts.ExtensionsParsed, _ = libgobuster.ParseExtensions(opts.Extensions)

	wordlist, err := os.CreateTemp(t.TempDir(), "words-*")
	if err != nil {
		t.Fatalf("could not create wordlist: %v", err)
	}
	if _, err := fmt.Fprint(wordlist, "admin\nadmin\ndashboard\n"); err != nil {
		t.Fatalf("could not write wordlist: %v", err)
	}
	if err := wordlist.Close(); err != nil {
		t.Fatalf("could not close wordlist: %v", err)
	}

	globalOpts := &libgobuster.Options{Threads: 2, Wordlist: wordlist.Name(), NoProgress: true}
	plugin, err := New(globalOpts, opts, libgobuster.NewLogger(false))
	if err != nil {
		t.Fatalf("could not create plugin: %v", err)
	}
	gobuster, err := libgobuster.NewGobuster(globalOpts, plugin, libgobuster.NewLogger(false))
	if err != nil {
		t.Fatalf("could not create gobuster: %v", err)
	}

	resultsChan := make(chan []Result, 1)
	go func() {
		results := make([]Result, 0)
		for result := range gobuster.Progress.ResultChan {
			resultDir, ok := result.(Result)
			if !ok {
				continue
			}
			results = append(results, resultDir)
		}
		resultsChan <- results
	}()

	if err := gobuster.Run(t.Context()); err != nil {
		t.Fatalf("run failed: %v", err)
	}

	results := <-resultsChan
	paths := make([]string, 0, len(results))
	for _, result := range results {
		paths = append(paths, strings.TrimSpace(result.Path))
		if result.ClusterID != 1 {
			t.Fatalf("result %s cluster = %d, want 1", result.Path, result.ClusterID)
		}
		output, err := result.ResultToString()
		if err != nil {
			t.Fatalf("could not format result: %v", err)
		}
		if !strings.Contains(output, "[Cluster: 1]") {
			t.Fatalf("missing cluster annotation in %q", output)
		}
	}
	sort.Strings(paths)
	expected := []string{"admin", "admin.html", "dashboard"}
	if strings.Join(paths, ",") != strings.Join(expected, ",") {
		t.Fatalf("deduplicated paths mismatch\nwant: %v\ngot:  %v", expected, paths)
	}
}

func staticSPAFixture() spaAcceptanceCase {
	fallback := `<!doctype html>
<html><head><title>Acme Console</title><link rel="stylesheet" href="/assets/app.css"></head>
<body><nav>Home Reports Settings</nav><main id="root"></main><script src="/assets/app.js"></script></body></html>`

	return spaAcceptanceCase{
		name: "static_fallback",
		server: func(t *testing.T) *httptest.Server {
			t.Helper()
			return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/admin":
					w.Header().Set("Content-Type", "text/html")
					_, _ = fmt.Fprint(w, `<!doctype html><html><head><title>Admin</title></head><body><main><h1>Administration</h1><table><tr><td>alice</td><td>owner</td></tr></table></main></body></html>`)
				case "/api":
					w.Header().Set("Content-Type", "application/json")
					_, _ = fmt.Fprint(w, `{"service":"inventory","version":"2.4.1","status":"ready"}`)
				case "/backup.zip":
					w.Header().Set("Content-Type", "application/zip")
					_, _ = fmt.Fprint(w, "PK\x03\x04fixture-backup-content")
				default:
					w.Header().Set("Content-Type", "text/html")
					_, _ = fmt.Fprint(w, fallback)
				}
			}))
		},
		words:    []string{"admin", "api", "backup.zip", "missing-one", "missing-two", "missing-three", "missing-four"},
		expected: []string{"admin", "api", "backup.zip"},
	}
}

func echoPathSPAFixture() spaAcceptanceCase {
	return spaAcceptanceCase{
		name: "reflected_path_fallback",
		server: func(t *testing.T) *httptest.Server {
			t.Helper()
			return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/reports":
					w.Header().Set("Content-Type", "text/html")
					_, _ = fmt.Fprintf(w, "<html><head><title>Reports</title></head><body><h1>Quarterly reports</h1><p>Revenue, cost and margin data for %s.</p></body></html>", r.URL.Path)
				case "/status":
					w.Header().Set("Content-Type", "text/html")
					w.Header().Set("X-App-Route", "status")
					_, _ = fmt.Fprintf(w, `<!doctype html><html><head><title>Acme Console</title><meta name="request-path" content="%s"></head><body><nav>Home Reports Settings</nav><main id="root">No route for %s</main><script src="/assets/app.js"></script></body></html>`, r.URL.Path, r.URL.Path)
				default:
					w.Header().Set("Content-Type", "text/html")
					_, _ = fmt.Fprintf(w, `<!doctype html><html><head><title>Acme Console</title><meta name="request-path" content="%s"></head><body><nav>Home Reports Settings</nav><main id="root">No route for %s</main><script src="/assets/app.js"></script></body></html>`, r.URL.Path, r.URL.Path)
				}
			}))
		},
		words:    []string{"reports", "status", "missing-alpha", "missing-beta", "missing-gamma", "missing-delta"},
		expected: []string{"reports", "status"},
	}
}

func dynamicSPAFixture() spaAcceptanceCase {
	var requestID atomic.Uint64

	return spaAcceptanceCase{
		name: "dynamic_nonce_fallback",
		server: func(t *testing.T) *httptest.Server {
			t.Helper()
			return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/dashboard":
					w.Header().Set("Content-Type", "text/html")
					_, _ = fmt.Fprint(w, `<!doctype html><html><head><title>Dashboard</title></head><body><nav>Home Reports Settings</nav><main><h1>Service dashboard</h1><section>CPU 42%</section><section>Memory 68%</section><section>Requests 12k/s</section></main></body></html>`)
				case "/health":
					w.Header().Set("Content-Type", "application/json")
					_, _ = fmt.Fprint(w, `{"status":"ok","checks":{"db":"ok","cache":"ok"},"uptime":98123}`)
				case "/robots.txt":
					w.Header().Set("Content-Type", "text/plain")
					_, _ = fmt.Fprint(w, "User-agent: *\nDisallow: /private\n")
				default:
					id := requestID.Add(1)
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					_, _ = fmt.Fprintf(w, `<!doctype html><html><head><title>Acme Console</title><meta name="csrf-token" content="%032x"><meta name="nonce" content="nonce-%d"></head><body data-request-id="%d"><nav>Home Reports Settings</nav><main id="root"><p>Requested %s at 2026-11-27T04:%02d:00Z</p></main><script nonce="%032x" src="/assets/app.js"></script></body></html>`, id, id, id, r.URL.Path, id%60, id+1000)
				}
			}))
		},
		words:    []string{"dashboard", "health", "robots.txt", "nope-one", "nope-two", "nope-three", "nope-four", "nope-five"},
		expected: []string{"dashboard", "health", "robots.txt"},
	}
}
