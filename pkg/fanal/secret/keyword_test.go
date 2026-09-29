package secret

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// candidateRules builds an index over the rules and lists the ones it lets
// through for the given content.
func candidateRules(rules []Rule, content []byte) []string {
	return selectedRules(newKeywordIndex(rules), rules, content)
}

// selectedRules lists the rules idx lets through for the given content.
func selectedRules(idx *keywordIndex, rules []Rule, content []byte) []string {
	found := idx.find(content)

	var ids []string
	for i, rule := range rules {
		if idx.hasKeyword(i, found) {
			ids = append(ids, rule.ID)
		}
	}
	return ids
}

// searchEachKeyword is the straightforward answer the index has to reproduce:
// look for every keyword on its own, ignoring ASCII case.
func searchEachKeyword(rules []Rule, content []byte) []string {
	return matchingRules(rules, []byte(foldASCIIString(string(content))), foldASCIIString)
}

// searchEachKeywordUnicode searches for every keyword on its own in a copy of
// the content lowercased by Unicode rules.
func searchEachKeywordUnicode(rules []Rule, content []byte) []string {
	return matchingRules(rules, bytes.ToLower(content), strings.ToLower)
}

func matchingRules(rules []Rule, lowered []byte, fold func(string) string) []string {
	var ids []string
	for _, rule := range rules {
		if len(rule.Keywords) == 0 {
			ids = append(ids, rule.ID)
			continue
		}
		for _, keyword := range rule.Keywords {
			if bytes.Contains(lowered, []byte(fold(keyword))) {
				ids = append(ids, rule.ID)
				break
			}
		}
	}
	return ids
}

var keywordTestRules = []Rule{
	{ID: "aws", Keywords: []string{"AWS"}},
	{ID: "twilio", Keywords: []string{"SK"}},
	{ID: "stripe", Keywords: []string{"sk_test_", "sk_live_"}},
	{ID: "no-keywords"},
}

var nonASCIIRules = []Rule{
	{ID: "aws", Keywords: []string{"AWS"}},
	{ID: "german", Keywords: []string{"ÖL"}},
}

var emptyKeywordRules = []Rule{
	{ID: "aws", Keywords: []string{"AWS"}},
	{ID: "empty-keyword", Keywords: []string{"", "AWS"}},
}

var suffixRules = []Rule{
	{ID: "access-token", Keywords: []string{"access_token"}},
	{ID: "token", Keywords: []string{"token"}},
}

// longKeyword is long enough for find to split any content that holds it.
var longKeyword = "begin_" + strings.Repeat("x", splitLen)

var longKeywordRules = []Rule{
	{ID: "long", Keywords: []string{longKeyword}},
	{ID: "aws", Keywords: []string{"AWS"}},
}

func TestKeywordIndex(t *testing.T) {
	tests := []struct {
		name    string
		rules   []Rule
		content string
		want    []string
	}{
		{
			name:    "empty content",
			content: "",
			want:    []string{"no-keywords"},
		},
		{
			name:    "keyword as written",
			content: "AWS_ACCESS_KEY_ID=AKIA0123",
			want:    []string{"aws", "no-keywords"},
		},
		{
			name:    "keyword in the other case",
			content: "aws_access_key_id=akia0123",
			want:    []string{"aws", "no-keywords"},
		},
		{
			name:    "keyword in mixed case",
			content: "Aws_Access_Key_Id=Akia0123",
			want:    []string{"aws", "no-keywords"},
		},
		{
			// "SK" is a prefix of "sk_test_", so a search that consumed the
			// shorter keyword would never see the longer one.
			name:    "keyword nested in a longer keyword",
			content: "key = sk_test_0123456789",
			want:    []string{"twilio", "stripe", "no-keywords"},
		},
		{
			name:    "second keyword of a rule",
			content: "key = sk_live_0123456789",
			want:    []string{"twilio", "stripe", "no-keywords"},
		},
		{
			name:    "keyword broken by a newline",
			content: "s\nk_test_0123456789",
			want:    []string{"no-keywords"},
		},
		{
			name:    "keyword at the very start",
			content: "AWS",
			want:    []string{"aws", "no-keywords"},
		},
		{
			name:    "keyword at the very end",
			content: "provider = aws",
			want:    []string{"aws", "no-keywords"},
		},
		{
			// The content is not valid UTF-8, which changes both the length and
			// the byte offsets of a Unicode lowercased copy of it.
			name:    "keyword after invalid utf-8",
			content: "\xff\xfe\xfd AWS_SECRET_ACCESS_KEY",
			want:    []string{"aws", "no-keywords"},
		},
		{
			// "token" is a suffix of "access_token", so it ends in the same
			// place and is reported only through the longer keyword's state.
			name:    "keyword ending a longer keyword",
			rules:   suffixRules,
			content: "ACCESS_TOKEN=0123456789",
			want:    []string{"access-token", "token"},
		},
		{
			name:    "keyword longer than the split",
			rules:   longKeywordRules,
			content: "value = " + longKeyword + " end",
			want:    []string{"long"},
		},
		{
			name:    "keyword longer than the split filling the content",
			rules:   longKeywordRules,
			content: longKeyword,
			want:    []string{"long"},
		},
		{
			// A keyword with a letter that has a case outside ASCII would be
			// found only as written, so the rule runs on every chunk.
			name:    "non-ASCII keyword absent",
			rules:   nonASCIIRules,
			content: "nothing here",
			want:    []string{"german"},
		},
		{
			name:    "non-ASCII keyword as written",
			rules:   nonASCIIRules,
			content: "provider = ÖL",
			want:    []string{"german"},
		},
		{
			name:    "non-ASCII keyword in the other case",
			rules:   nonASCIIRules,
			content: "provider = öl",
			want:    []string{"german"},
		},
		{
			name:    "non-ASCII keyword next to an indexed one",
			rules:   nonASCIIRules,
			content: "provider = aws",
			want:    []string{"aws", "german"},
		},
		{
			// U+0130 lowercases to "i" but has no case folding.
			name:    "non-ASCII keyword that lowercases into ASCII",
			rules:   []Rule{{ID: "dotted-i", Keywords: []string{"İD"}}},
			content: "user id",
			want:    []string{"dotted-i"},
		},
		{
			// An empty keyword occurs in any content, so the rule runs even
			// when its other keywords are absent.
			name:    "empty keyword",
			rules:   emptyKeywordRules,
			content: "nothing here",
			want:    []string{"empty-keyword"},
		},
		{
			name:    "empty keyword next to a found one",
			rules:   emptyKeywordRules,
			content: "provider = aws",
			want:    []string{"aws", "empty-keyword"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules := tt.rules
			if rules == nil {
				rules = keywordTestRules
			}
			assert.ElementsMatch(t, tt.want, candidateRules(rules, []byte(tt.content)))
		})
	}
}

// The index folds ASCII case only, so a keyword spelled with a non-ASCII
// character that lowercases into ASCII is found by Unicode lowercasing but not
// by the index.
func TestKeywordIndexFoldsASCIIOnly(t *testing.T) {
	kelvin := "sK_test_0123456789" // U+212A KELVIN SIGN in place of K

	assert.Equal(t, []string{"no-keywords"}, candidateRules(keywordTestRules, []byte(kelvin)))
	assert.Equal(t, []string{"twilio", "stripe", "no-keywords"},
		searchEachKeywordUnicode(keywordTestRules, []byte(kelvin)))
}

// Without a keyword to look for there is no index, and every rule runs.
func TestKeywordIndexNotBuilt(t *testing.T) {
	rules := []Rule{
		{ID: "first"},
		{ID: "second"},
		{ID: "empty-keyword", Keywords: []string{""}},
	}
	idx := newKeywordIndex(rules)
	require.Nil(t, idx, "no index is built when no rule has a keyword to look for")
	assert.Equal(t, []string{"first", "second", "empty-keyword"},
		selectedRules(idx, rules, []byte("nothing here")))
}

// Over every file in testdata, the index and the plain search have to pick the
// same rules, and so does the search over Unicode lowercased content, since
// ASCII folding must give the same answer on real content.
func TestKeywordIndexOnTestdata(t *testing.T) {
	entries, err := os.ReadDir("testdata")
	require.NoError(t, err)
	require.NotEmpty(t, entries)

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		content, err := os.ReadFile(filepath.Join("testdata", entry.Name()))
		require.NoError(t, err)
		t.Run(entry.Name(), func(t *testing.T) {
			want := searchEachKeywordUnicode(builtinRules, content)
			assert.ElementsMatch(t, want, searchEachKeyword(builtinRules, content))
			assert.ElementsMatch(t, want, candidateRules(builtinRules, content))
		})
	}
}

// TestKeywordIndexAcrossSplit walks a keyword over every offset of content long
// enough for find to split it between two chains. A keyword lying across the
// split is what such a scan loses if the two halves do not overlap far enough.
func TestKeywordIndexAcrossSplit(t *testing.T) {
	keyword := []byte("sk_test_")
	idx := newKeywordIndex(keywordTestRules)

	for _, size := range []int{splitLen - 1, splitLen, splitLen + 1, 4096} {
		for offset := 0; offset+len(keyword) <= size; offset++ {
			content := bytes.Repeat([]byte("."), size)
			copy(content[offset:], keyword)

			want := searchEachKeyword(keywordTestRules, content)
			got := selectedRules(idx, keywordTestRules, content)
			require.ElementsMatchf(t, want, got, "size %d, offset %d", size, offset)
		}
	}
}

// fuzzRules makes a rule of every line of spec, with its keywords separated by
// commas. Keywords the index cannot use are dropped, since searchEachKeyword
// does not run such a rule on every chunk.
func fuzzRules(spec string) []Rule {
	var rules []Rule
	for line := range strings.SplitSeq(spec, "\n") {
		rule := Rule{ID: strconv.Itoa(len(rules))}
		for keyword := range strings.SplitSeq(line, ",") {
			if !unusableKeyword(keyword) {
				rule.Keywords = append(rule.Keywords, keyword)
			}
		}
		rules = append(rules, rule)
	}
	return rules
}

func FuzzKeywordIndex(f *testing.F) {
	const testRules = "AWS\nSK\nsk_test_,sk_live_"
	f.Add(testRules, "AWS_SECRET_ACCESS_KEY=0123456789")
	f.Add(testRules, "key = sk_test_0123456789")
	f.Add(testRules, "\xff\xfe\xfd sk_live_0123456789")
	f.Add(testRules, "")
	f.Add("access_token\ntoken", "ACCESS_TOKEN=0123456789")
	f.Add(longKeyword+"\nx", strings.Repeat(".", splitLen)+longKeyword)

	var many []string
	for i := range 70 {
		many = append(many, fmt.Sprintf("key%02d", i))
	}
	f.Add(strings.Join(many, "\n"), "value = KEY65")

	f.Fuzz(func(t *testing.T, spec, content string) {
		rules := fuzzRules(spec)
		got := candidateRules(rules, []byte(content))
		assert.ElementsMatch(t, searchEachKeyword(rules, []byte(content)), got)
	})
}
