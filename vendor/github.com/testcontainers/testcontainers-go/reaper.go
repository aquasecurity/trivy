package testcontainers

import (
	"bufio"
	"context"
	"fmt"
	"github.com/docker/go-connections/nat"
	"github.com/testcontainers/testcontainers-go/wait"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
)

const (
	TestcontainerLabel          = "org.testcontainers.golang"
	TestcontainerLabelSessionID = TestcontainerLabel + ".sessionId"
	TestcontainerLabelIsReaper  = TestcontainerLabel + ".reaper"

	ReaperDefaultImage = "quay.io/testcontainers/ryuk:0.2.3"
)

var reaper *Reaper // We would like to create reaper only once
var mutex sync.Mutex

// ReaperProvider represents a provider for the reaper to run itself with
// The ContainerProvider interface should usually satisfy this as well, so it is pluggable
type ReaperProvider interface {
	RunContainer(ctx context.Context, req ContainerRequest) (Container, error)
}

// Reaper is used to start a sidecar container that cleans up resources
type Reaper struct {
	Provider  ReaperProvider
	SessionID string
	Endpoint  string
}

// NewReaper creates a Reaper with a sessionID to identify containers and a provider to use
func NewReaper(ctx context.Context, sessionID string, provider ReaperProvider, reaperImageName string) (*Reaper, error) {
	mutex.Lock()
	defer mutex.Unlock()
	// If reaper already exists re-use it
	if reaper != nil {
		return reaper, nil
	}

	// Otherwise create a new one
	reaper = &Reaper{
		Provider:  provider,
		SessionID: sessionID,
	}

	listeningPort := nat.Port("8080/tcp")

	req := ContainerRequest{
		Image:        reaperImage(reaperImageName),
		ExposedPorts: []string{string(listeningPort)},
		Labels: map[string]string{
			TestcontainerLabel:         "true",
			TestcontainerLabelIsReaper: "true",
		},
		SkipReaper: true,
		BindMounts: map[string]string{
			"/var/run/docker.sock": "/var/run/docker.sock",
		},
		AutoRemove: true,
		WaitingFor: wait.ForListeningPort(listeningPort),
	}

	// Attach reaper container to a requested network if it is specified
	if p, ok := provider.(*DockerProvider); ok {
		req.Networks = append(req.Networks, p.defaultNetwork)
	}

	c, err := provider.RunContainer(ctx, req)
	if err != nil {
		return nil, err
	}

	endpoint, err := c.PortEndpoint(ctx, "8080", "")
	if err != nil {
		return nil, err
	}
	reaper.Endpoint = endpoint

	return reaper, nil
}

func reaperImage(reaperImageName string) string {
	if reaperImageName == "" {
		return ReaperDefaultImage
	} else {
		return reaperImageName
	}
}

// Connect runs a goroutine which can be terminated by sending true into the returned channel
func (r *Reaper) Connect() (chan bool, error) {
	conn, err := net.DialTimeout("tcp", r.Endpoint, 10*time.Second)
	if err != nil {
		return nil, errors.Wrap(err, "Connecting to Ryuk on "+r.Endpoint+" failed")
	}

	terminationSignal := make(chan bool)
	go func(conn net.Conn) {
		sock := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
		defer conn.Close()

		labelFilters := []string{}
		for l, v := range r.Labels() {
			labelFilters = append(labelFilters, fmt.Sprintf("label=%s=%s", l, v))
		}

		retryLimit := 3
		for retryLimit > 0 {
			retryLimit--

			sock.WriteString(strings.Join(labelFilters, "&"))
			sock.WriteString("\n")
			if err := sock.Flush(); err != nil {
				continue
			}

			resp, err := sock.ReadString('\n')
			if err != nil {
				continue
			}
			if resp == "ACK\n" {
				break
			}
		}

		<-terminationSignal
	}(conn)
	return terminationSignal, nil
}

// Labels returns the container labels to use so that this Reaper cleans them up
func (r *Reaper) Labels() map[string]string {
	return map[string]string{
		TestcontainerLabel:          "true",
		TestcontainerLabelSessionID: r.SessionID,
	}
}
