package gobusterdir

import (
	"fmt"
	"net/http"
	"testing"
)

func TestResponseFingerprintDynamicFallback(t *testing.T) {
	t.Parallel()

	header := http.Header{"Content-Type": []string{"text/html; charset=utf-8"}}
	first := NewResponseFingerprint(200, []byte(`<html><head><title>App</title><meta name="csrf-token" content="a3b1c4d5e6f7890a3b1c4d5e6f7890a3"></head><body data-request-id="91"><p>Requested /missing-one at 2026-11-27T04:01:00Z</p><script nonce="a3b1c4d5e6f7890a3b1c4d5e6f7890a3" src="/app.js"></script></body></html>`), header, "/missing-one")
	second := NewResponseFingerprint(200, []byte(`<html><head><title>App</title><meta name="csrf-token" content="b4c2d5e6f7890ab4c2d5e6f7890ab4c2"></head><body data-request-id="92"><p>Requested /missing-two at 2026-11-27T04:02:00Z</p><script nonce="b4c2d5e6f7890ab4c2d5e6f7890ab4c2" src="/app.js"></script></body></html>`), header, "/missing-two")

	similarity := first.Similarity(second)
	t.Logf("similarity: %.4f", similarity)
	if similarity < 0.90 {
		t.Fatalf("dynamic fallback responses should be similar, got %.4f", similarity)
	}

	detector := NewSoft404Detector([]ResponseFingerprint{first, second}, DefaultSoft404Threshold)
	if detector == nil {
		t.Fatal("expected a soft-404 detector")
	}
	if !detector.Match(first) {
		t.Fatal("expected probe fingerprint to match itself")
	}
}

func TestSoft404DetectorRejectsUnstableWildcard(t *testing.T) {
	t.Parallel()

	header := http.Header{"Content-Type": []string{"text/plain"}}
	samples := make([]ResponseFingerprint, 0, 3)
	for i := range 3 {
		body := fmt.Sprintf("random response %d: %s", i, "completely different body content")
		samples = append(samples, NewResponseFingerprint(200, []byte(body), header, fmt.Sprintf("/missing-%d", i)))
	}

	if detector := NewSoft404Detector(samples, DefaultSoft404Threshold); detector != nil {
		t.Fatal("unstable wildcard responses must not be treated as soft-404")
	}
}

func TestResultClusterer(t *testing.T) {
	t.Parallel()

	header := http.Header{"Content-Type": []string{"text/html"}}
	admin := NewResponseFingerprint(200, []byte("<html><body><h1>Admin</h1><table>users</table></body></html>"), header, "/admin")
	adminAlias := NewResponseFingerprint(200, []byte("<html><body><h1>Admin</h1><table>users</table></body></html>"), header, "/manage")
	health := NewResponseFingerprint(200, []byte(`{"status":"ok","database":"online"}`), http.Header{"Content-Type": []string{"application/json"}}, "/health")

	clusterer := NewResultClusterer(DefaultClusterThreshold)
	if got := clusterer.Add(admin); got != 1 {
		t.Fatalf("first cluster id = %d, want 1", got)
	}
	if got := clusterer.Add(adminAlias); got != 1 {
		t.Fatalf("similar cluster id = %d, want 1", got)
	}
	if got := clusterer.Add(health); got != 2 {
		t.Fatalf("different cluster id = %d, want 2", got)
	}
}

func TestResponseFingerprintStableHeadersSeparateRoutes(t *testing.T) {
	t.Parallel()

	body := []byte("<html><body><main>same body</main></body></html>")
	fallback := NewResponseFingerprint(200, body, http.Header{
		"Content-Type":   []string{"text/html"},
		"X-Spa-Fallback": []string{"true"},
		"X-Request-Id":   []string{"first-random-value"},
	}, "/missing")
	valid := NewResponseFingerprint(200, body, http.Header{
		"Content-Type":   []string{"text/html"},
		"X-Spa-Fallback": []string{"false"},
		"X-Request-Id":   []string{"second-random-value"},
	}, "/valid")

	if similarity := fallback.Similarity(valid); similarity != 0 {
		t.Fatalf("stable header difference should separate responses, got %.2f", similarity)
	}
}

func TestResultDeduplication(t *testing.T) {
	t.Parallel()

	plugin := &GobusterDir{
		options:     &OptionsDir{Deduplicate: true},
		seenResults: make(map[string]struct{}),
	}
	if !plugin.claimResult("https://example.test/found") {
		t.Fatal("first result must be accepted")
	}
	if plugin.claimResult("https://example.test/found") {
		t.Fatal("duplicate result must be rejected")
	}
}
