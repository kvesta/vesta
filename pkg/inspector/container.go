package inspector

import (
	"context"
	"io"
	"log"
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

func (da *DockerApi) GetContainerName(containerID string) ([]io.ReadCloser, error) {
	var whiteList = []string{"/", "/etc", "/proc",
		"/sys", "/usr", "/lib", "/lib64"}
	var containerIo []io.ReadCloser

	isWhite := func(path string) bool {
		for _, whitePath := range whiteList {
			if path == whitePath {
				return true
			}
		}

		return false
	}

	log.Printf(config.Green("Searching for container"))
	fileio, err := da.DCli.ContainerExport(ctx, containerID)

	if err != nil {
		return nil, err
	}

	containerIo = append(containerIo, fileio)

	// Get mount path, reference: https://docs.docker.com/engine/reference/commandline/export/#description
	ins, err := da.getInspect(containerID)
	if err == nil {
		var mnts []types.MountPoint
		if ins.Mounts != nil {
			mnts = ins.Mounts
		}

		for _, mnt := range mnts {
			if isWhite(mnt.Source) {
				continue
			}

			cp, stats, err := da.DCli.CopyFromContainer(ctx, containerID, mnt.Destination)
			if err != nil || stats.Size > 1073741824 {
				continue
			}

			containerIo = append(containerIo, cp)
		}
	}

	return containerIo, err
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
