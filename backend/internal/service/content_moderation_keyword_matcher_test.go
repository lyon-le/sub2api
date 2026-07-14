package service

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
)

func TestContentModerationKeywordMatcherMatchesLegacyBehavior(t *testing.T) {
	tests := []struct {
		name     string
		text     string
		keywords []string
	}{
		{name: "miss", text: "clean prompt", keywords: []string{"blocked", "secret"}},
		{name: "case insensitive", text: "contains SECRET value", keywords: []string{"secret"}},
		{name: "configured order wins", text: "early appears before later", keywords: []string{"later", "early"}},
		{name: "overlap uses configured order", text: "abc", keywords: []string{"bc", "abc"}},
		{name: "unicode", text: "这里包含敏感词和世界", keywords: []string{"世界", "敏感词"}},
		{name: "duplicates", text: "duplicate", keywords: []string{"duplicate", "DUPLICATE"}},
		{name: "empty entries", text: "blocked", keywords: []string{"", "blocked"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantKeyword, wantHit := matchBlockedKeyword(tt.text, tt.keywords)
			gotKeyword, gotHit := newContentModerationKeywordMatcher(tt.keywords).Match(tt.text)
			require.Equal(t, wantHit, gotHit)
			require.Equal(t, wantKeyword, gotKeyword)
		})
	}
}

func TestContentModerationKeywordMatcherRandomizedParity(t *testing.T) {
	rng := rand.New(rand.NewSource(20260714))
	const alphabet = "abcXYZ"
	for iteration := 0; iteration < 1000; iteration++ {
		keywords := make([]string, 1+rng.Intn(30))
		for index := range keywords {
			length := 1 + rng.Intn(8)
			var value strings.Builder
			for range length {
				value.WriteByte(alphabet[rng.Intn(len(alphabet))])
			}
			keywords[index] = value.String()
		}
		var text strings.Builder
		for range 20 + rng.Intn(100) {
			text.WriteByte(alphabet[rng.Intn(len(alphabet))])
		}

		wantKeyword, wantHit := matchBlockedKeyword(text.String(), keywords)
		gotKeyword, gotHit := newContentModerationKeywordMatcher(keywords).Match(text.String())
		require.Equal(t, wantHit, gotHit, "iteration %d", iteration)
		require.Equal(t, wantKeyword, gotKeyword, "iteration %d", iteration)
	}
}

func TestContentModerationKeywordMatcherMaximumConfigResidentMemory(t *testing.T) {
	keywords := maximumContentModerationKeywords()
	matcher := newContentModerationKeywordMatcher(keywords)
	require.NotNil(t, matcher)
	residentBytes := contentModerationKeywordMatcherResidentBytes(matcher)
	t.Logf("matcher nodes=%d edges=%d resident_bytes=%d", len(matcher.nodes), len(matcher.edges), residentBytes)
	require.LessOrEqual(t, residentBytes, int64(128*1024*1024))
}

func TestContentModerationKeywordMatcherMaximumConfigReplacementMemory(t *testing.T) {
	keywords := maximumContentModerationKeywords()
	previous := newContentModerationKeywordMatcher(keywords)
	replacement := newContentModerationKeywordMatcher(keywords)
	combinedResidentBytes := contentModerationKeywordMatcherResidentBytes(previous) + contentModerationKeywordMatcherResidentBytes(replacement)
	t.Logf("combined_resident_bytes=%d", combinedResidentBytes)
	require.LessOrEqual(t, combinedResidentBytes, int64(256*1024*1024))
	runtime.KeepAlive(previous)
	runtime.KeepAlive(replacement)
}

func maximumContentModerationKeywords() []string {
	keywords := make([]string, maxContentModerationBlockedKeywords)
	for index := range keywords {
		sum := sha256.Sum256([]byte(fmt.Sprintf("keyword-%d", index)))
		seed := hex.EncodeToString(sum[:])
		keywords[index] = (strings.Repeat(seed, 4))[:maxContentModerationBlockedKeywordRunes]
	}
	return keywords
}

func contentModerationKeywordMatcherResidentBytes(matcher *contentModerationKeywordMatcher) int64 {
	if matcher == nil {
		return 0
	}
	total := int64(unsafe.Sizeof(*matcher))
	total += int64(cap(matcher.nodes)) * int64(unsafe.Sizeof(contentModerationKeywordNode{}))
	total += int64(cap(matcher.edges)) * int64(unsafe.Sizeof(contentModerationKeywordEdge{}))
	total += int64(cap(matcher.keywords)) * int64(unsafe.Sizeof(""))
	for _, keyword := range matcher.keywords {
		total += int64(len(keyword))
	}
	return total
}

var (
	contentModerationKeywordBenchmarkSinkKeyword string
	contentModerationKeywordBenchmarkSinkHit     bool
)

func BenchmarkContentModerationKeywordMatching(b *testing.B) {
	const (
		keywordCount = 500
		textLength   = 12000
	)
	keywords := make([]string, keywordCount)
	for index := range keywords {
		keywords[index] = fmt.Sprintf("blocked-keyword-%05d-z", index)
	}
	matcher := newContentModerationKeywordMatcher(keywords)
	tailKeyword := strings.ToUpper(keywords[len(keywords)-1])
	scenarios := []struct {
		name string
		text string
	}{
		{name: "miss", text: strings.Repeat("a", textLength)},
		{name: "tail_hit", text: strings.Repeat("a", textLength-len(tailKeyword)-1) + " " + tailKeyword},
	}

	for _, scenario := range scenarios {
		legacyKeyword, legacyHit := matchBlockedKeyword(scenario.text, keywords)
		matcherKeyword, matcherHit := matcher.Match(scenario.text)
		require.Equal(b, legacyKeyword, matcherKeyword)
		require.Equal(b, legacyHit, matcherHit)

		b.Run("legacy/"+scenario.name, func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				contentModerationKeywordBenchmarkSinkKeyword, contentModerationKeywordBenchmarkSinkHit = matchBlockedKeyword(scenario.text, keywords)
			}
		})
		b.Run("aho_corasick/"+scenario.name, func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				contentModerationKeywordBenchmarkSinkKeyword, contentModerationKeywordBenchmarkSinkHit = matcher.Match(scenario.text)
			}
		})
	}
}
