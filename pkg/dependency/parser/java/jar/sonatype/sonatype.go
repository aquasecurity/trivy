package sonatype

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/java/jar"
)

const (
	baseURL         = "https://search.maven.org/solrsearch/select"
	idQuery         = `g:"%s" AND a:"%s"`
	artifactIdQuery = `a:"%s" AND p:"jar"`
	sha1Query       = `1:"%s"`
)

type apiResponse struct {
	Response struct {
		NumFound int `json:"numFound"`
		Docs     []struct {
			ID           string `json:"id"`
			GroupID      string `json:"g"`
			ArtifactID   string `json:"a"`
			Version      string `json:"v"`
			P            string `json:"p"`
			VersionCount int    `json:"versionCount"`
		} `json:"docs"`
	} `json:"response"`
}

type Sonatype struct {
	baseURL    string
	httpClient *http.Client
}

type Option func(*Sonatype)

func WithURL(url string) Option {
	return func(p *Sonatype) {
		p.baseURL = url
	}
}

func WithHTTPClient(client *http.Client) Option {
	return func(p *Sonatype) {
		p.httpClient = client
	}
}

func New(opts ...Option) Sonatype {
	// for HTTP retry
	retryClient := retryablehttp.NewClient()
	retryClient.Logger = newLogger()
	retryClient.RetryWaitMin = 20 * time.Second
	retryClient.RetryWaitMax = 5 * time.Minute
	retryClient.RetryMax = 5
	client := retryClient.StandardClient()

	// attempt to read the maven central api url from os environment, if it's
	// not set use the default
	mavenURL, ok := os.LookupEnv("MAVEN_CENTRAL_URL")
	if !ok {
		mavenURL = baseURL
	}

	s := Sonatype{
		baseURL:    mavenURL,
		httpClient: client,
	}

	for _, opt := range opts {
		opt(&s)
	}

	return s
}

func (s Sonatype) Exists(groupID, artifactID string) (bool, error) {
	req, err := http.NewRequest(http.MethodGet, s.baseURL, http.NoBody)
	if err != nil {
		return false, xerrors.Errorf("unable to initialize HTTP client: %w", err)
	}

	q := req.URL.Query()
	q.Set("q", fmt.Sprintf(idQuery, groupID, artifactID))
	q.Set("rows", "1")
	req.URL.RawQuery = q.Encode()

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return false, xerrors.Errorf("http error: %w", err)
	}
	defer resp.Body.Close()

	var res apiResponse
	if err = json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return false, xerrors.Errorf("json decode error: %w", err)
	}
	return res.Response.NumFound > 0, nil
}

func (s Sonatype) SearchBySHA1(sha1 string) (jar.Properties, error) {

	req, err := http.NewRequest(http.MethodGet, s.baseURL, http.NoBody)
	if err != nil {
		return jar.Properties{}, xerrors.Errorf("unable to initialize HTTP client: %w", err)
	}

	q := req.URL.Query()
	q.Set("q", fmt.Sprintf(sha1Query, sha1))
	q.Set("rows", "1")
	q.Set("wt", "json")
	req.URL.RawQuery = q.Encode()

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return jar.Properties{}, xerrors.Errorf("sha1 search error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return jar.Properties{}, xerrors.Errorf("status %s from %s", resp.Status, req.URL.String())
	}

	var res apiResponse
	if err = json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return jar.Properties{}, xerrors.Errorf("json decode error: %w", err)
	}

	if len(res.Response.Docs) == 0 {
		return jar.Properties{}, xerrors.Errorf("digest %s: %w", sha1, jar.ArtifactNotFoundErr)
	}

	// Some artifacts might have the same SHA-1 digests.
	// e.g. "javax.servlet:jstl" and "jstl:jstl"
	docs := res.Response.Docs
	sort.Slice(docs, func(i, j int) bool {
		return docs[i].ID < docs[j].ID
	})
	d := docs[0]

	return jar.Properties{
		GroupID:    d.GroupID,
		ArtifactID: d.ArtifactID,
		Version:    d.Version,
	}, nil
}

func (s Sonatype) SearchByArtifactID(artifactID, _ string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, s.baseURL, http.NoBody)
	if err != nil {
		return "", xerrors.Errorf("unable to initialize HTTP client: %w", err)
	}

	q := req.URL.Query()
	q.Set("q", fmt.Sprintf(artifactIdQuery, artifactID))
	q.Set("rows", "20")
	q.Set("wt", "json")
	req.URL.RawQuery = q.Encode()

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", xerrors.Errorf("artifactID search error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", xerrors.Errorf("status %s from %s", resp.Status, req.URL.String())
	}

	var res apiResponse
	if err = json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return "", xerrors.Errorf("json decode error: %w", err)
	}

	if len(res.Response.Docs) == 0 {
		return "", xerrors.Errorf("artifactID %s: %w", artifactID, jar.ArtifactNotFoundErr)
	}

	// Some artifacts might have the same artifactId.
	// e.g. "javax.servlet:jstl" and "jstl:jstl"
	docs := res.Response.Docs
	sort.Slice(docs, func(i, j int) bool {
		return docs[i].VersionCount > docs[j].VersionCount
	})
	d := docs[0]

	return d.GroupID, nil
}
