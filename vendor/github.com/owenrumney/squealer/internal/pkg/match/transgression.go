package match

import (
	"fmt"
	"strings"

	"github.com/go-git/go-git/v5/plumbing/object"
)

type Transgression struct {
	LineContent      string
	Filename         string
	Hash             string
	Match            string
	MatchDescription string
	RedactedContent  string
	Committer        string
	CommitterEmail   string
	CommitHash       string
	ExcludeRule      string
	Committed        string
	LineNo           int
}

func newTransgression(lineNo int, lineContent, filename, match, matchDescription, hash string, commit *object.Commit) Transgression {
	content := strings.TrimSpace(lineContent)

	commitHash := "-- not applicable --"
	committerName := "-- not applicable --"
	committerEmail := ""
	when := "-- not applicable --"
	if commit != nil {
		commitHash = commit.Hash.String()
		committerEmail = commit.Committer.Email
		committerName = commit.Committer.Name
		when = commit.Committer.When.String()
	}

	return Transgression{
		LineNo:           lineNo,
		LineContent:      content,
		Filename:         filename,
		Hash:             hash,
		Match:            match,
		MatchDescription: matchDescription,
		RedactedContent:  strings.ReplaceAll(content, match, "REDACTED"),
		Committer:        committerName,
		CommitterEmail:   committerEmail,
		Committed:        when,
		CommitHash:       commitHash,
		ExcludeRule:      fmt.Sprintf("%s:%s", filename, hash),
	}
}

func (t *Transgression) update(t2 Transgression) {
	t.Committer = t2.Committer
	t.CommitterEmail = t2.CommitterEmail
	t.CommitHash = t2.CommitHash
	t.Committed = t2.Committed
	t.LineContent = t2.LineContent
	t.LineNo = t2.LineNo
}
