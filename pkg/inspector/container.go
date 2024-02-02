package inspector

import (
	"context"
	"io"
	"log"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/kvesta/vesta/config"
)

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
	ins, err := da.DCli.ContainerInspect(ctx, containerID)

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
			// Skip the large file
			if err != nil || stats.Size > 1073741824 {
				continue
			}

			containerIo = append(containerIo, cp)
		}
	}

	return containerIo, err
}

func (da *DockerApi) GetAllContainers() ([]*types.ContainerJSON, error) {
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
		ins, err := da.DCli.ContainerInspect(ctx, c.ID[:12])
		if err != nil {
			log.Printf("%s cannot inpsect, error: %v", c.Names, err)
		}
		inps = append(inps, &ins)
	}

	return inps, nil
}

func (da *DockerApi) GetEngineVersion(ctx context.Context) (string, error) {
	log.Printf("Getting engine version")

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

func (da *DockerApi) GetDockerServerVersion(ctx context.Context) (string, error) {
	log.Printf("Getting docker server version")

	var version string

	server, err := da.DCli.ServerVersion(ctx)
	if err != nil {
		return version, err
	}

	version = server.Version

	return version, nil
}

func (da *DockerApi) FindDockerService(name string) bool {
	sws, err := da.DCli.ServiceList(context.Background(), types.ServiceListOptions{})

	if err != nil {
		return false
	}

	for _, swarm := range sws {
		if strings.HasPrefix(name, swarm.Spec.Name) {
			return true
		}
	}

	return false
}
