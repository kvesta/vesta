package inspector

import (
	"context"

	"github.com/docker/docker/client"
)

var (
	ctx = context.Background()
)

type DockerApi struct {
	DCli *client.Client
}
