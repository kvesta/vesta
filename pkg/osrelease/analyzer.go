package osrelease

import (
	"context"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"regexp"
	"strings"

	"github.com/kvesta/vesta/pkg/layer"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

// Reference https://manpages.ubuntu.com/manpages/bionic/zh_TW/man5/os-release.5.html
var paths = []string{"etc/os-release", "etc/centos-release", "etc/photon-release", "usr/lib/os-release"}

func KernelParse(kernel string) string {
	filter := regexp.MustCompile(`[a-zA-Z]`)
	begin := filter.FindStringIndex(kernel)[0]
	value := strings.Split(kernel[begin:], " ")
	return value[2]

}

// GetKernelVersion get kernel version from host machine
// using `docker run` command so that to adapt to docker-desktop
// kata-container is not taken into account yet
func GetKernelVersion(ctx context.Context) (string, error) {
	log.Printf("Geting kernel version")
	var kernel string

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())

	if err != nil {
		return "", err
	}

	defer cli.Close()

	images, err := cli.ImageList(ctx, types.ImageListOptions{})
	if err != nil {
		if strings.Contains(err.Error(), "Is the docker daemon running?") {
			err = errors.New("docker is not running")
			return "", err
		}
		return "", err
	}

	var busyboxImage = false
	for _, image := range images {
		if len(image.RepoTags) < 1 {
			continue
		}

		repotag := image.RepoTags[0]
		if strings.Contains(repotag, "busybox:1.34.1") {
			busyboxImage = true
		}
	}

	if !busyboxImage {
		log.Printf("Pulling busybox:1.34.1 image for kernel checking")
		reader, err := cli.ImagePull(ctx, "busybox:1.34.1", types.ImagePullOptions{})
		if err != nil {
			return "", err
		}
		defer reader.Close()

		// Waiting for pulling image
		ioutil.ReadAll(reader)
	}

	resp, err := cli.ContainerCreate(ctx, &container.Config{
		Image: "busybox:1.34.1",
		Cmd: []string{"cat",
			"/proc/version"},
		Tty: false,
	},
		nil, nil, nil, "kernel-checking")
	if err != nil {
		return "", err
	}
	if err := cli.ContainerStart(ctx, resp.ID, types.ContainerStartOptions{}); err != nil {
		return "", err
	}

	defer func() {
		removeOptions := types.ContainerRemoveOptions{
			RemoveVolumes: true,
			Force:         true,
		}

		if err := cli.ContainerRemove(ctx, resp.ID, removeOptions); err != nil {
			log.Printf("Unable to remove container %s: %s", resp.ID, err)
		}
	}()

	statusCh, errCh := cli.ContainerWait(ctx, resp.ID, container.WaitConditionNotRunning)
	select {
	case err = <-errCh:
		if err != nil {
			return "", err
		}
	case <-statusCh:
	}

	out, err := cli.ContainerLogs(ctx, resp.ID, types.ContainerLogsOptions{ShowStdout: true})
	if err != nil {
		return "", err
	}

	res := strings.Builder{}
	_, err = io.Copy(&res, out)
	if err != nil {
		return "", err
	}

	kernel = KernelParse(res.String())

	return kernel, nil
}

// DetectOs get os version
func DetectOs(ctx context.Context, m layer.Manifest) (*OsVersion, error) {
	osv := &OsVersion{
		NAME: "Linux",
		OID:  "linux",
	}

	for _, n := range paths {
		rd, err := m.File(n)
		if err != nil {
			log.Printf("detect os error: %v", err)
			continue
		}
		config := rd.String()
		if config != "" {
			osv, err = getOs(config, n)
			if err != nil {
				log.Printf("parse os error: %v", err)
			}
			break
		}
	}

	return osv, nil

}

func parse(config, path string) (map[string]string, error) {
	lines := strings.Split(config, "\n")
	m := make(map[string]string)
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		versionRegex := regexp.MustCompile(`(\d+\.)?(\d+\.)?(\*|\d+)$`)
		switch path {
		case "etc/os-release", "usr/lib/os-release":
			index := strings.Index(line, "=")
			if index > -1 {
				values := strings.Split(line, "=")
				values[1] = strings.Replace(values[1], `"`, "", -1)
				m[values[0]] = values[1]
			}
		case "etc/centos-release":
			m["NAME"] = "CentOS Linux"
			m["OID"] = "CentOS"
			m["VERSION_ID"] = versionRegex.FindString(line)

		case "etc/photon-release":
			index := strings.Index(line, "=")
			if index > -1 {
				values := strings.Split(line, "=")
				m["VERSION"] = values[1]
			} else {
				m["NAME"] = "VMware Photon OS"
				m["OID"] = "Photon"
				m["VERSION_ID"] = versionRegex.FindString(line)
			}
		default:
			// ignore
		}
	}
	return m, nil
}

func getOs(config, path string) (*OsVersion, error) {
	kv, err := parse(config, path)
	if err != nil {
		return nil, err
	}
	os := &OsVersion{
		NAME: "Linux",
		OID:  "linux",
	}
	for k, v := range kv {
		switch k {
		case "NAME":
			os.NAME = v
		case "OID":
			os.OID = v
		case "VERSION":
			os.VERSION = v
		case "VERSION_ID":
			os.VERSION_ID = v
		}
	}
	return os, nil
}
