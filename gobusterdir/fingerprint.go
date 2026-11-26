package gobusterdir

import (
	"crypto/sha256"
	"encoding/binary"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

const (
	// DefaultSoft404Threshold is the default similarity needed to classify a
	// response as the detected soft-404 fallback.
	DefaultSoft404Threshold = 0.92
	// DefaultClusterThreshold is the default similarity used to group results.
	DefaultClusterThreshold = 0.88
	defaultSoft404Probes    = 3
)

// nolint:gochecknoglobals
var fingerprintDynamicPatterns = []struct {
	re          *regexp.Regexp
	replacement string
}{
	{regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`), "{{dynamic}}"},
	{regexp.MustCompile(`(?i)\b[0-9a-f]{16,}\b`), "{{dynamic}}"},
	{regexp.MustCompile(`\b[A-Za-z0-9+/_-]{24,}={0,2}\b`), "{{dynamic}}"},
	{regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b`), "{{time}}"},
	{regexp.MustCompile(`\b\d{10,13}\b`), "{{time}}"},
	{regexp.MustCompile(`(?i)(nonce|csrf(?:token)?|authenticity_token|requestid|traceid)(["']?\s*[:=]\s*["']?)[A-Za-z0-9._~+/=-]{8,}`), "${1}${2}{{dynamic}}"},
	{regexp.MustCompile(`(?i)(\b(?:nonce|csrf(?:token)?|authenticity_token|request[-_]?id|trace[-_]?id|correlation[-_]?id|build[-_]?id|deployment[-_]?id|session[-_]?id|token)=")[^"]*(")`), "${1}{{dynamic}}${2}"},
	{regexp.MustCompile(`(?i)(\b(?:nonce|csrf(?:token)?|authenticity_token|request[-_]?id|trace[-_]?id|correlation[-_]?id|build[-_]?id|deployment[-_]?id|session[-_]?id|token)\s*[:=]\s*)[A-Za-z0-9._~+/=-]+`), "${1}{{dynamic}}"},
	{regexp.MustCompile(`(?i)(data-[a-z0-9_-]+=")[^"]*(")`), "${1}{{dynamic}}${2}"},
	{regexp.MustCompile(`(?i)(<meta[^>]*\bcontent=")[^"]*(")`), "${1}{{dynamic}}${2}"},
	{regexp.MustCompile(`(?i)(<input[^>]*\bvalue=")[^"]{12,}(")`), "${1}{{dynamic}}${2}"},
	{regexp.MustCompile(`(?i)([?&](?:v|ver|version|ts|t|_)=)[^"&\s<]+`), "${1}{{dynamic}}"},
}

// ResponseFingerprint is a normalized representation of an HTTP response used
// for soft-404 detection and similarity clustering.
type ResponseFingerprint struct {
	StatusCode      int
	Length          int64
	ContentType     string
	Location        string
	HeaderSignature string

	bodyHash [sha256.Size]byte
	tokens   map[uint64]struct{}
}

// NewResponseFingerprint creates a fingerprint from the response body, headers
// and the request path. Dynamic values such as UUIDs, nonces and reflected
// paths are normalized so repeated SPA fallback responses compare as equal.
func NewResponseFingerprint(statusCode int, body []byte, header http.Header, requestPath string) ResponseFingerprint {
	contentType := strings.ToLower(strings.TrimSpace(strings.Split(header.Get("Content-Type"), ";")[0]))
	location := normalizeFingerprintString(header.Get("Location"), requestPath)
	normalizedBody := normalizeFingerprintString(string(body), requestPath)

	return ResponseFingerprint{
		StatusCode:      statusCode,
		Length:          int64(len(body)),
		ContentType:     contentType,
		Location:        location,
		HeaderSignature: headerFingerprint(header, requestPath),
		bodyHash:        sha256.Sum256([]byte(normalizedBody)),
		tokens:          fingerprintShingles(normalizedBody),
	}
}

// Similarity returns a value between 0 and 1 describing how similar two
// responses are. Status code, content type and stable headers are hard
// boundaries.
func (f ResponseFingerprint) Similarity(other ResponseFingerprint) float64 {
	if f.StatusCode != other.StatusCode {
		return 0
	}

	if f.ContentType != "" && other.ContentType != "" && f.ContentType != other.ContentType {
		return 0
	}

	if f.HeaderSignature != other.HeaderSignature {
		return 0
	}

	if f.bodyHash == other.bodyHash && f.Location == other.Location {
		return 1
	}

	if f.Location != "" || other.Location != "" {
		if f.Location == other.Location {
			return 1
		}
		return 0
	}

	if len(f.tokens) == 0 || len(other.tokens) == 0 {
		return 0
	}

	intersection := 0
	for token := range f.tokens {
		if _, found := other.tokens[token]; found {
			intersection++
		}
	}

	union := len(f.tokens) + len(other.tokens) - intersection
	if union == 0 {
		return 0
	}
	return float64(intersection) / float64(union)
}

// Soft404Detector recognizes responses that are equivalent to the fallback
// response returned for random non-existing paths.
type Soft404Detector struct {
	samples   []ResponseFingerprint
	threshold float64
}

// NewSoft404Detector builds a detector from random-path probe responses. It
// returns nil when the probes are not consistent enough to form a reliable
// fallback fingerprint.
func NewSoft404Detector(samples []ResponseFingerprint, threshold float64) *Soft404Detector {
	if len(samples) < 2 {
		return nil
	}
	if threshold <= 0 || threshold > 1 {
		threshold = DefaultSoft404Threshold
	}

	probeThreshold := threshold - 0.10
	if probeThreshold < 0.70 {
		probeThreshold = 0.70
	}

	consistent := make([]ResponseFingerprint, 0, len(samples))
	for i, sample := range samples {
		best := 0.0
		for j, other := range samples {
			if i == j {
				continue
			}
			if score := sample.Similarity(other); score > best {
				best = score
			}
		}
		if best >= probeThreshold {
			consistent = append(consistent, sample)
		}
	}

	if len(consistent) < 2 {
		return nil
	}

	return &Soft404Detector{
		samples:   consistent,
		threshold: threshold,
	}
}

// Match reports whether the response belongs to the detected soft-404
// fingerprint family.
func (d *Soft404Detector) Match(fingerprint ResponseFingerprint) bool {
	if d == nil {
		return false
	}
	return d.Similarity(fingerprint) >= d.threshold
}

// Similarity returns the closest similarity to any probe response.
func (d *Soft404Detector) Similarity(fingerprint ResponseFingerprint) float64 {
	if d == nil {
		return 0
	}
	best := 0.0
	for _, sample := range d.samples {
		if score := sample.Similarity(fingerprint); score > best {
			best = score
		}
	}
	return best
}

type resultCluster struct {
	id          int
	fingerprint ResponseFingerprint
}

// ResultClusterer groups successful results by response similarity while
// retaining every unique path.
type ResultClusterer struct {
	mu        sync.Mutex
	threshold float64
	clusters  []resultCluster
}

// NewResultClusterer creates a similarity clusterer.
func NewResultClusterer(threshold float64) *ResultClusterer {
	if threshold <= 0 || threshold > 1 {
		threshold = DefaultClusterThreshold
	}
	return &ResultClusterer{threshold: threshold}
}

// Add assigns a fingerprint to the most similar cluster and returns its ID.
func (c *ResultClusterer) Add(fingerprint ResponseFingerprint) int {
	if c == nil {
		return 0
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	bestIndex := -1
	bestScore := 0.0
	for i := range c.clusters {
		score := c.clusters[i].fingerprint.Similarity(fingerprint)
		if score >= c.threshold && score > bestScore {
			bestScore = score
			bestIndex = i
		}
	}

	if bestIndex >= 0 {
		return c.clusters[bestIndex].id
	}

	id := len(c.clusters) + 1
	c.clusters = append(c.clusters, resultCluster{
		id:          id,
		fingerprint: fingerprint,
	})
	return id
}

func normalizeFingerprintString(input, requestPath string) string {
	if input == "" {
		return ""
	}

	normalized := html.UnescapeString(input)
	for _, path := range fingerprintPathVariants(requestPath) {
		normalized = strings.ReplaceAll(normalized, path, "{{path}}")
	}

	for _, pattern := range fingerprintDynamicPatterns {
		normalized = pattern.re.ReplaceAllString(normalized, pattern.replacement)
	}

	normalized = strings.ToLower(normalized)
	normalized = strings.Join(strings.Fields(normalized), " ")
	return normalized
}

func headerFingerprint(header http.Header, requestPath string) string {
	names := make([]string, 0, len(header))
	for name := range header {
		if isVolatileFingerprintHeader(name) {
			continue
		}
		names = append(names, http.CanonicalHeaderKey(name))
	}
	sort.Strings(names)

	var signature strings.Builder
	for _, name := range names {
		signature.WriteString(strings.ToLower(name))
		signature.WriteByte('=')
		values := header.Values(name)
		for i, value := range values {
			if i > 0 {
				signature.WriteByte(',')
			}
			signature.WriteString(normalizeFingerprintString(value, requestPath))
		}
		signature.WriteByte(';')
	}
	return signature.String()
}

func isVolatileFingerprintHeader(name string) bool {
	switch http.CanonicalHeaderKey(name) {
	case "Age", "Akamai-Request-Id", "Cf-Cache-Status", "Cf-Ray", "Connection",
		"Content-Length", "Content-Type", "Date", "Etag", "Expires", "Last-Modified",
		"Location", "Request-Id", "Server-Timing", "Set-Cookie", "Traceparent",
		"Tracestate", "Transfer-Encoding", "X-Amz-Cf-Id", "X-Amzn-Trace-Id",
		"X-Cache", "X-Cache-Status", "X-Correlation-Id", "X-Request-Id",
		"X-Trace-Id", "X-Varnish":
		return true
	default:
		return false
	}
}

func fingerprintPathVariants(requestPath string) []string {
	if requestPath == "" {
		return nil
	}

	variants := map[string]struct{}{requestPath: {}}
	trimmed := strings.TrimPrefix(requestPath, "/")
	if trimmed != "" {
		variants[trimmed] = struct{}{}
	}
	if escaped := url.PathEscape(requestPath); escaped != requestPath {
		variants[escaped] = struct{}{}
	}
	if escaped := url.PathEscape(trimmed); escaped != trimmed {
		variants[escaped] = struct{}{}
	}

	result := make([]string, 0, len(variants))
	for variant := range variants {
		if len(variant) > 1 {
			result = append(result, variant)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return len(result[i]) > len(result[j])
	})
	return result
}

func fingerprintShingles(input string) map[uint64]struct{} {
	tokens := fingerprintTokens(input)
	if len(tokens) == 0 {
		return nil
	}

	shingles := make(map[uint64]struct{}, len(tokens))
	if len(tokens) < 4 {
		for _, token := range tokens {
			shingles[token] = struct{}{}
		}
		return shingles
	}

	for i := 0; i+4 <= len(tokens); i++ {
		shingles[hashFingerprintTokens(tokens[i:i+4])] = struct{}{}
	}
	return shingles
}

func fingerprintTokens(input string) []uint64 {
	tokens := make([]uint64, 0, len(input)/8)
	var word strings.Builder

	flushWord := func() {
		if word.Len() == 0 {
			return
		}
		tokens = append(tokens, hashFingerprintString("w:"+word.String()))
		word.Reset()
	}

	for i := 0; i < len(input); {
		r := rune(input[i])
		if r < utf8.RuneSelf {
			switch {
			case unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '-':
				word.WriteByte(input[i])
				i++
				continue
			case r == '<':
				flushWord()
				start := i + 1
				end := start
				for end < len(input) {
					c := rune(input[end])
					if c == '/' || c == '>' || unicode.IsSpace(c) {
						break
					}
					end++
				}
				if end > start {
					tokens = append(tokens, hashFingerprintString("t:"+input[start:end]))
				}
			}
			flushWord()
			i++
			continue
		}

		flushWord()
		i++
	}
	flushWord()
	return tokens
}

func hashFingerprintTokens(tokens []uint64) uint64 {
	hash := uint64(1469598103934665603)
	var buffer [8]byte
	for _, token := range tokens {
		binary.LittleEndian.PutUint64(buffer[:], token)
		for _, b := range buffer {
			hash ^= uint64(b)
			hash *= 1099511628211
		}
	}
	return hash
}

func hashFingerprintString(input string) uint64 {
	hash := uint64(1469598103934665603)
	for i := 0; i < len(input); i++ {
		hash ^= uint64(input[i])
		hash *= 1099511628211
	}
	return hash
}
