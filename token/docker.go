package token

import "context"

type Docker struct {
}

func NewDocker() *Docker {
	return &Docker{}
}

func (d *Docker) GetCredential(ctx context.Context) (username, password string, err error) {
	return "", "", nil
}
