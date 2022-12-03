package inspector

import (
	"context"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/kvesta/vesta/config"

	"github.com/docker/docker/api/types"
)

func (da DockerApi) getInspect(imageID string) (*types.ContainerJSON, error) {
	var ins types.ContainerJSON
	ins, err := da.DCli.ContainerInspect(ctx, imageID)
	if err != nil {
		return &ins, err
	}
	return &ins, nil
}

func (da *DockerApi) GetContainerName(containerID string) (string, error) {
	var containerList []string

	containers, err := da.DCli.ContainerList(ctx, types.ContainerListOptions{})
	if err != nil {
		return "", err
	}

	// Do not use the `all` option temporary
	if strings.ToLower(containerID) == "all" {
		for _, container := range containers {
			containerList = append(containerList, container.ID[:12])
		}
	}

	log.Printf(config.Green("Searching container"))
	fileio, err := da.DCli.ContainerExport(ctx, containerID)

	if err != nil {
		return "", err
	}
	pwd, _ := os.Getwd()
	tarFile := filepath.Join(pwd, "output.tar")
	file, _ := os.OpenFile(tarFile, os.O_CREATE|os.O_RDWR, 0666)

	_, err = io.Copy(file, fileio)
	if err != nil {
		return "", err
	}

	return tarFile, nil
}

func (da DockerApi) GetAllContainers() ([]*types.ContainerJSON, error) {
	inps := []*types.ContainerJSON{}
	containers, err := da.DCli.ContainerList(ctx, types.ContainerListOptions{})
	if err != nil {
		return inps, err
	}
	for _, c := range containers {
		// pass the kubernetes pod for kubernetes version < 1.24
		if strings.Contains(c.Names[0], "k8s") {
			continue
		}
		ins, err := da.getInspect(c.ID[:12])
		if err != nil {
			log.Printf("%s can not inpsect, error: %v", c.Names, err)
		}
		inps = append(inps, ins)
	}

	return inps, nil
}

func (da DockerApi) GetEngineVersion(ctx context.Context) (string, error) {
	log.Printf("Geting engine version")

	var version string

	server, err := da.DCli.ServerVersion(ctx)
	if err != nil {
		return version, err
	}
	for _, s := range server.Components {
		if s.Name == "containerd" {
			version = s.Version
			break
		}
	}

	return version, err
}

func (da DockerApi) GetDockerServerVersion(ctx context.Context) (string, error) {
	log.Printf("Geting docker server version")

	var version string

	server, err := da.DCli.ServerVersion(ctx)
	if err != nil {
		return version, err
	}

	version = server.Version

	return version, nil
}
