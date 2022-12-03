package inspector

import (
	"context"
	"github.com/docker/docker/client"
	"log"
)

func GetTarFromID(ctx context.Context, ID string) (string, error) {
	var err error
	// Use the inspector id from containerd or crio
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Printf("init docker environment failed: %v", err)
		return "", err
	}
	c := DockerApi{
		DCli: cli,
	}

	defer c.DCli.Close()

	var tarFile string
	if ctx.Value("tarType") == "image" {
		tarFile, err = c.GetImageName(ID)
	} else {
		tarFile, err = c.GetContainerName(ID)
		if err != nil {
			log.Printf("expose inspector file error: %v", err)
			return "", err
		}

	}

	return tarFile, nil
}
