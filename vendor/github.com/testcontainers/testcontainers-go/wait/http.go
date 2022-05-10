package wait

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/docker/go-connections/nat"
)

// Implement interface
var _ Strategy = (*HTTPStrategy)(nil)

type HTTPStrategy struct {
	// all Strategies should have a startupTimeout to avoid waiting infinitely
	startupTimeout time.Duration

	// additional properties
	Port              nat.Port
	Path              string
	StatusCodeMatcher func(status int) bool
	ResponseMatcher   func(body io.Reader) bool
	UseTLS            bool
	AllowInsecure     bool
	TLSConfig         *tls.Config // TLS config for HTTPS
	Method            string      // http method
	Body              io.Reader   // http request body
	PollInterval      time.Duration
}

// NewHTTPStrategy constructs a HTTP strategy waiting on port 80 and status code 200
func NewHTTPStrategy(path string) *HTTPStrategy {
	return &HTTPStrategy{
		startupTimeout:    defaultStartupTimeout(),
		Port:              "80/tcp",
		Path:              path,
		StatusCodeMatcher: defaultStatusCodeMatcher,
		ResponseMatcher:   func(body io.Reader) bool { return true },
		UseTLS:            false,
		TLSConfig:         nil,
		Method:            http.MethodGet,
		Body:              nil,
		PollInterval:      defaultPollInterval(),
	}
}

func defaultStatusCodeMatcher(status int) bool {
	return status == http.StatusOK
}

// fluent builders for each property
// since go has neither covariance nor generics, the return type must be the type of the concrete implementation
// this is true for all properties, even the "shared" ones like startupTimeout

func (ws *HTTPStrategy) WithStartupTimeout(startupTimeout time.Duration) *HTTPStrategy {
	ws.startupTimeout = startupTimeout
	return ws
}

func (ws *HTTPStrategy) WithPort(port nat.Port) *HTTPStrategy {
	ws.Port = port
	return ws
}

func (ws *HTTPStrategy) WithStatusCodeMatcher(statusCodeMatcher func(status int) bool) *HTTPStrategy {
	ws.StatusCodeMatcher = statusCodeMatcher
	return ws
}

func (ws *HTTPStrategy) WithResponseMatcher(matcher func(body io.Reader) bool) *HTTPStrategy {
	ws.ResponseMatcher = matcher
	return ws
}

func (ws *HTTPStrategy) WithTLS(useTLS bool, tlsconf ...*tls.Config) *HTTPStrategy {
	ws.UseTLS = useTLS
	if useTLS && len(tlsconf) > 0 {
		ws.TLSConfig = tlsconf[0]
	}
	return ws
}

func (ws *HTTPStrategy) WithAllowInsecure(allowInsecure bool) *HTTPStrategy {
	ws.AllowInsecure = allowInsecure
	return ws
}

func (ws *HTTPStrategy) WithMethod(method string) *HTTPStrategy {
	ws.Method = method
	return ws
}

func (ws *HTTPStrategy) WithBody(reqdata io.Reader) *HTTPStrategy {
	ws.Body = reqdata
	return ws
}

// WithPollInterval can be used to override the default polling interval of 100 milliseconds
func (ws *HTTPStrategy) WithPollInterval(pollInterval time.Duration) *HTTPStrategy {
	ws.PollInterval = pollInterval
	return ws
}

// ForHTTP is a convenience method similar to Wait.java
// https://github.com/testcontainers/testcontainers-java/blob/1d85a3834bd937f80aad3a4cec249c027f31aeb4/core/src/main/java/org/testcontainers/containers/wait/strategy/Wait.java
func ForHTTP(path string) *HTTPStrategy {
	return NewHTTPStrategy(path)
}

// WaitUntilReady implements Strategy.WaitUntilReady
func (ws *HTTPStrategy) WaitUntilReady(ctx context.Context, target StrategyTarget) (err error) {
	// limit context to startupTimeout
	ctx, cancelContext := context.WithTimeout(ctx, ws.startupTimeout)
	defer cancelContext()

	ipAddress, err := target.Host(ctx)
	if err != nil {
		return
	}

	var port nat.Port
	port, err = target.MappedPort(ctx, ws.Port)

	for port == "" {
		select {
		case <-ctx.Done():
			return fmt.Errorf("%s:%w", ctx.Err(), err)
		case <-time.After(ws.PollInterval):
			port, err = target.MappedPort(ctx, ws.Port)
		}
	}

	if port.Proto() != "tcp" {
		return errors.New("Cannot use HTTP client on non-TCP ports")
	}

	switch ws.Method {
	case http.MethodGet, http.MethodHead, http.MethodPost,
		http.MethodPut, http.MethodPatch, http.MethodDelete,
		http.MethodConnect, http.MethodOptions, http.MethodTrace:
	default:
		if ws.Method != "" {
			return fmt.Errorf("invalid http method %q", ws.Method)
		}
		ws.Method = http.MethodGet
	}

	tripper := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       ws.TLSConfig,
	}

	var proto string
	if ws.UseTLS {
		proto = "https"
		if ws.AllowInsecure {
			if ws.TLSConfig == nil {
				tripper.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
			} else {
				ws.TLSConfig.InsecureSkipVerify = true
			}
		}
	} else {
		proto = "http"
	}

	client := http.Client{Transport: tripper, Timeout: time.Second}
	address := net.JoinHostPort(ipAddress, strconv.Itoa(port.Int()))
	endpoint := fmt.Sprintf("%s://%s%s", proto, address, ws.Path)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(ws.PollInterval):
			req, err := http.NewRequestWithContext(ctx, ws.Method, endpoint, ws.Body)
			if err != nil {
				return err
			}
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			if ws.StatusCodeMatcher != nil && !ws.StatusCodeMatcher(resp.StatusCode) {
				continue
			}
			if ws.ResponseMatcher != nil && !ws.ResponseMatcher(resp.Body) {
				continue
			}
			if err := resp.Body.Close(); err != nil {
				continue
			}
			return nil
		}
	}
}
