package azure_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/image/registry/azure"
)

const (
	// msiEndpointEnv is the environment variable used to store the endpoint on App Service and Functions
	msiEndpointEnv = "MSI_ENDPOINT"

	// the format for expires_on in UTC without AM/PM
	expiresOnDateFormat = "1/2/2006 15:04:05 +00:00"
)

func newTokenJSON(expiresIn string, expiresOn time.Time, resource string) string {
	return fmt.Sprintf(`{
		"access_token" : "accessToken",
		"expires_in"   : %s,
		"expires_on"   : "%s",
		"not_before"   : "%s",
		"resource"     : "%s",
		"token_type"   : "Bearer",
		"refresh_token": "FANAL123"
		}`,
		expiresIn, expiresOn.Format(expiresOnDateFormat), timeToDuration(expiresOn), resource)
}

func timeToDuration(t time.Time) json.Number {
	dur := t.Sub(time.Now().UTC())
	return json.Number(strconv.FormatInt(int64(dur.Round(time.Second).Seconds()), 10))
}

func tokenHandle(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(200)
	w.Header().Add("Content-Type", "application/json")

	expiresOn := time.Now().UTC().Add(time.Hour)
	fmt.Fprint(w, newTokenJSON("3600", expiresOn, "test"))
}

func TestAzureTokenMSI(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/metadata/identity/oauth2/token", tokenHandle)
	mux.HandleFunc("/oauth2/exchange", tokenHandle)

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	t.Setenv(msiEndpointEnv, fmt.Sprintf("%s/metadata/identity/oauth2/token", server.URL))

	aa, err := azure.NewACRCredStore()
	require.NoError(t, err)

	aa.SetExchangeScheme("http")

	token, err := aa.Get(context.Background(), strings.Replace(server.URL, "http://", "", -1))

	require.NoError(t, err)
	assert.Equal(t, *token, "FANAL123")
}

func TestAzureTokenCredentials(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/exchange", tokenHandle)
	mux.HandleFunc("/oauth2/token", tokenHandle)

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	t.Setenv("AZURE_CLIENT_SECRET", "Test")
	t.Setenv("AZURE_CLIENT_ID", "Test")

	aa, err := azure.NewACRCredStore()
	require.Empty(t, err)

	aa.SetExchangeScheme("http")
	aa.SetActiveDirectoryEndpoint(server.URL)

	token, err := aa.Get(context.Background(), strings.Replace(server.URL, "http://", "", -1))

	require.NoError(t, err)
	assert.Equal(t, *token, "FANAL123")
}

func TestAzureTokenCredentialsError(t *testing.T) {
	t.Setenv("AZURE_CLIENT_SECRET", "Test")

	aa, err := azure.NewACRCredStore()
	require.NoError(t, err)

	_, err = aa.Get(context.Background(), "")
	assert.Error(t, err)
}
