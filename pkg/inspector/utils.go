package inspector

import (
	"context"
	"io"
	"log"

	"github.com/docker/docker/client"
)

func GetTarFromID(ctx context.Context, ID string) ([]io.ReadCloser, error) {
	var err error

	// Use the inspector id from containerd or crio
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Printf("init docker environment failed: %v", err)
		return nil, err
	}
	c := DockerApi{
		DCli: cli,
	}

	defer c.DCli.Close()

	var tarFile []io.ReadCloser

	if ctx.Value("tarType") == "image" {
		tarFile, err = c.GetImageName(ID)
		if err != nil {
			log.Printf("get image error: %v", err)
		}
	} else {
		tarFile, err = c.GetContainerName(ID)
		if err != nil {
			log.Printf("expose inspector file error: %v", err)
			return nil, err
		}

	}

	return tarFile, nil
}
