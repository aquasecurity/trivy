package secret

import (
	"bytes"
	"os"
	"path/filepath"
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

// searchEachKeywordUnicode is how the keywords were searched before the index,
// over a copy of the content lowercased by Unicode rules.
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

func TestKeywordIndex(t *testing.T) {
	tests := []struct {
		name    string
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := candidateRules(keywordTestRules, []byte(tt.content))
			assert.ElementsMatch(t, tt.want, got)
			assert.ElementsMatch(t, searchEachKeyword(keywordTestRules, []byte(tt.content)), got)
		})
	}
}

// The index folds ASCII case only, and this pins the places where that answers
// differently from the Unicode lowercasing the scanner used before. wantUnicode
// is what the old search found there, and it is filled in only for the rows
// where the two disagree.
func TestKeywordIndexFoldsASCIIOnly(t *testing.T) {
	kelvin := "sK_test_0123456789" // U+212A KELVIN SIGN in place of K
	germanRules := []Rule{{ID: "german", Keywords: []string{"ÖL"}}}

	tests := []struct {
		name        string
		rules       []Rule
		content     string
		want        []string
		wantUnicode []string
	}{
		{
			name:        "non-ascii character in the content",
			rules:       keywordTestRules,
			content:     kelvin,
			want:        []string{"no-keywords"},
			wantUnicode: []string{"twilio", "stripe", "no-keywords"},
		},
		{
			name:    "non-ascii keyword as written",
			rules:   germanRules,
			content: "provider = ÖL",
			want:    []string{"german"},
		},
		{
			// Only the ASCII part of the keyword ignores case.
			name:    "ascii letter of the keyword in the other case",
			rules:   germanRules,
			content: "provider = Öl",
			want:    []string{"german"},
		},
		{
			name:        "non-ascii letter of the keyword in the other case",
			rules:       germanRules,
			content:     "provider = öl",
			wantUnicode: []string{"german"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, candidateRules(tt.rules, []byte(tt.content)))

			wantUnicode := tt.wantUnicode
			if wantUnicode == nil {
				wantUnicode = tt.want
			}
			assert.Equal(t, wantUnicode, searchEachKeywordUnicode(tt.rules, []byte(tt.content)))
		})
	}
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

// An empty keyword occurs in any content, so a rule that has one always runs,
// even when its other keywords are absent.
func TestKeywordIndexEmptyKeyword(t *testing.T) {
	rules := []Rule{
		{ID: "aws", Keywords: []string{"AWS"}},
		{ID: "empty-keyword", Keywords: []string{"", "AWS"}},
	}

	assert.Equal(t, []string{"empty-keyword"}, candidateRules(rules, []byte("nothing here")))
	assert.Equal(t, []string{"aws", "empty-keyword"}, candidateRules(rules, []byte("provider = aws")))
}

// Over every file in testdata, the index and the plain search have to pick the
// same rules. The old Unicode search answers as well, so the switch to ASCII
// folding has to change nothing on real content.
func TestKeywordIndexOnTestdata(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "*"))
	require.NoError(t, err)
	require.NotEmpty(t, files)

	for _, file := range files {
		content, err := os.ReadFile(file)
		if err != nil {
			continue // directories and anything unreadable
		}
		t.Run(filepath.Base(file), func(t *testing.T) {
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

func FuzzKeywordIndex(f *testing.F) {
	f.Add("AWS_SECRET_ACCESS_KEY=0123456789")
	f.Add("key = sk_test_0123456789")
	f.Add("\xff\xfe\xfd sk_live_0123456789")
	f.Add("")

	idx := newKeywordIndex(keywordTestRules)

	f.Fuzz(func(t *testing.T, content string) {
		got := selectedRules(idx, keywordTestRules, []byte(content))
		assert.ElementsMatch(t, searchEachKeyword(keywordTestRules, []byte(content)), got)
	})
}
