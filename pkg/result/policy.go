package result

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"

	"github.com/open-policy-agent/opa/rego"
	"golang.org/x/xerrors"
)

type PolicyStore interface {
	Evaluate(ctx context.Context, input interface{}) (bool, error)
}

type LocalPolicyStore struct {
	query rego.PreparedEvalQuery
}

func NewLocalPolicyStore(ctx context.Context, policyFile string) (PolicyStore, error) {
	policy, err := ioutil.ReadFile(policyFile)
	if err != nil {
		err = xerrors.Errorf("unable to read policy file %s: %w", policyFile, err)
		return nil, err
	}

	query, err := rego.New(
		rego.Query("data.trivy.ignore"),
		rego.Module("lib.rego", module),
		rego.Module("trivy.rego", string(policy)),
	).PrepareForEval(ctx)
	if err != nil {
		return nil, xerrors.Errorf("unable to prepare for eval: %w", err)
	}

	return &LocalPolicyStore{query: query}, nil
}

func (l *LocalPolicyStore) Evaluate(ctx context.Context, input interface{}) (bool, error) {
	results, err := l.query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return false, xerrors.Errorf("unable to evaluate the policy: %w", err)
	} else if len(results) == 0 {
		// Handle undefined result.
		return false, nil
	}
	ignore, ok := results[0].Expressions[0].Value.(bool)
	if !ok {
		// Handle unexpected result type.
		return false, xerrors.New("the policy must return boolean")
	}
	return ignore, nil
}

type RemotePolicyStore struct {
	remoteURL string
}

func NewRemotePolicyStore(remoteAddr string) (PolicyStore, error) {
	u, err := url.Parse(remoteAddr)
	if err != nil {
		return nil, err
	}
	u.Path = path.Join(u.Path, "/v1/data/trivy/ignore")

	return &RemotePolicyStore{
		remoteURL: u.String(),
	}, nil
}

func (r *RemotePolicyStore) Evaluate(ctx context.Context, input interface{}) (bool, error) {
	reqBody, err := processQueryInput(input)
	if err != nil {
		return false, xerrors.Errorf("unable to process policy input: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", r.remoteURL, reqBody)
	if err != nil {
		err = xerrors.Errorf("unable to create new policy request: %w", err)
		return false, err
	}
	req.Header.Add("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		err = xerrors.Errorf("unable to send query policy request: %w", err)
		return false, err
	}

	return processQueryResult(resp)
}

func processQueryInput(input interface{}) (io.Reader, error) {
	type opaRequest struct {
		Input interface{} `json:"input"`
	}

	inputData := opaRequest{Input: input}
	inputBytes, err := json.Marshal(&inputData)
	if err != nil {
		err = xerrors.Errorf("unable to marshal input data: %w", err)
		return nil, err
	}
	return bytes.NewReader(inputBytes), nil

}

func processQueryResult(resp *http.Response) (bool, error) {
	type opaResult struct {
		Result  bool
		Warning struct {
			Code    string
			Message string
		}
	}
	var queryResult opaResult
	var err error
	var respBytes []byte

	// From the API doc of OPA, non-HTTP 200 response codes indicate configuration
	// or runtime errors.
	if resp.StatusCode != http.StatusOK {
		err = xerrors.Errorf("unable to get query result, response code is %d, want 200 instead", resp.StatusCode)
		return false, err
	}
	if respBytes, err = ioutil.ReadAll(resp.Body); err != nil {
		err = xerrors.Errorf("unable to read query response: %w", err)
		return false, err
	}
	if err = json.Unmarshal(respBytes, &queryResult); err != nil {
		err = xerrors.Errorf("unable to unmarshal query response: %w", err)
		return false, err
	}

	return queryResult.Result, nil
}
