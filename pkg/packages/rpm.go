package packages

import (
	"context"
	"io"
	"io/ioutil"
	"log"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/client"
)

var (
	ctx context.Context
	cli *client.Client
	err error
)

func init() {
	ctx = context.Background()
}

func getCentOsImage() (bool, error) {
	cli, err = client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return false, err
	}
	images, err := cli.ImageList(ctx, types.ImageListOptions{})
	if err != nil {
		return false, err
	}

	for _, image := range images {
		if len(image.RepoTags) < 1 {
			continue
		}
		repotag := image.RepoTags[0]
		if strings.Contains(repotag, "redhat/ubi9-minimal:9.0.0") {
			return true, nil
		}
	}
	return false, nil
}

// getRpmPacks use rpm command from /bin/bash or docker
func (s *Packages) getRpmPacks(ctx context.Context) error {
	if ok, err := getRpmPacksFromRpm(s.Mani.Localpath, s); !ok {
		log.Printf("Executing rpm command error, error %v", err)
	} else {
		return nil
	}

	log.Printf("Using docker command to parse")
	exist, err := getCentOsImage()
	if err != nil {
		log.Printf("Check centos inspector failed, error %v", err)
		return err
	}

	// Close the docker client here
	defer cli.Close()

	if !exist {
		log.Printf("Pulling redhat/ubi9-minimal:9.0.0 inspector")
		reader, err := cli.ImagePull(ctx, "redhat/ubi9-minimal:9.0.0", types.ImagePullOptions{})
		if err != nil {
			return err
		}

		defer reader.Close()

		// Waiting for pulling image
		ioutil.ReadAll(reader)
	}

	packagePath := filepath.Join(s.Mani.Localpath, "var/lib/rpm")
	resp, err := cli.ContainerCreate(ctx, &container.Config{
		Image: "redhat/ubi9-minimal:9.0.0",
		Cmd: []string{"rpm",
			"-qa",
			"--root", "/tmp", "--dbpath", "/",
			"--queryformat", "%{NAME} %{VERSION}-%{RELEASE} %{ARCH}\n"},
		Tty: false,
	},
		&container.HostConfig{
			Mounts: []mount.Mount{
				{
					Type:   mount.TypeBind,
					Source: packagePath,
					Target: "/tmp",
				},
			},
		}, nil, nil, "rpm-parsing")
	if err != nil {
		log.Printf("Contianer initial failed, error %v", err)
		return err
	}
	if err := cli.ContainerStart(ctx, resp.ID, types.ContainerStartOptions{}); err != nil {
		log.Printf("Container creat failed, error %v", err)
		return err
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
			log.Printf("Container creat failed, error %v", err)
			return err
		}
	case <-statusCh:
	}

	out, err := cli.ContainerLogs(ctx, resp.ID, types.ContainerLogsOptions{ShowStdout: true})
	if err != nil {
		log.Printf("Container execute failed, error %v", err)
		return err
	}

	rpm := strings.Builder{}
	_, err = io.Copy(&rpm, out)
	if err != nil {
		log.Printf("faile to io copy in rpm, error: %v", err)
		return err
	}
	s.RpmParse(rpm.String())

	return nil
}

func getRpmPacksFromRpm(path string, s *Packages) (bool, error) {
	rpmPath := filepath.Join(path, "var/lib/rpm")
	cmd := exec.Command("rpm", "-qa",
		`--root`, rpmPath, `--dbpath`, "/",
		`--queryformat`, "%{NAME} %{VERSION}-%{RELEASE} %{ARCH}\n")

	if err = cmd.Start(); err != nil {
		if strings.Contains(err.Error(), "executable file not found") {
			return false, nil
		}
		return false, err
	}

	rpm, err := cmd.Output()
	if err != nil {
		return false, err
	}

	if string(rpm) == "" {
		return false, nil
	}

	s.RpmParse(string(rpm))
	return true, nil
}

func (s *Packages) RpmParse(rpm string) {
	packs := strings.Split(rpm, "\n")
	for _, pe := range packs {
		if len(pe) < 1 {
			continue
		}
		p := &Package{}
		filter := regexp.MustCompile(`[a-zA-Z]`)
		begin := filter.FindStringIndex(pe)[0]
		value := strings.Split(pe[begin:], " ")
		p.Name = value[0]
		p.Version = value[1]
		p.Architecture = value[2]
		s.Packs = append(s.Packs, p)
	}
}
