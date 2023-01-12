package analyzer

import (
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"strings"

	"github.com/docker/docker/api/types"
	version2 "github.com/hashicorp/go-version"
	_config "github.com/kvesta/vesta/config"
	_image "github.com/kvesta/vesta/pkg/inspector"
	"github.com/kvesta/vesta/pkg/vulnlib"
	"github.com/tidwall/gjson"
)

func (s *Scanner) checkDockerContext(ctx context.Context, images []*_image.ImageInfo) error {

	cli := vulnlib.Client{}
	err := cli.Init()

	if err != nil {
		log.Printf("failed to init database, error: %v", err)
	} else {
		defer cli.DB.Close()
	}

	// Checking kernel version
	if ok, tlist := checkKernelVersion(cli); ok {
		ct := &container{
			ContainerID:   "None",
			ContainerName: "Kernel",
			Threats:       tlist,
		}

		s.VulnContainers = append(s.VulnContainers, ct)
	}

	// Check Docker server version
	if ok, tlist := checkDockerVersion(cli, s.ServerVersion); ok {
		ct := &container{
			ContainerID:   "None",
			ContainerName: "Server Version",
			Threats:       tlist,
		}

		s.VulnContainers = append(s.VulnContainers, ct)
	}

	// Check 2375 unauthorized
	if ok, tlist := checkDockerUnauthorized(); ok {
		ct := &container{
			ContainerID:   "None",
			ContainerName: "Docker 2375 port",
			Threats:       tlist,
		}

		s.VulnContainers = append(s.VulnContainers, ct)
	}

	// Check the repo's tag
	if ok, tlist := checkImages(images); ok {
		ct := &container{
			ContainerID:   "None",
			ContainerName: "Image Tag",
			Threats:       tlist,
		}

		s.VulnContainers = append(s.VulnContainers, ct)
	}

	// Check image's history
	if ok, tlist := checkHistories(images); ok {
		ct := &container{
			ContainerID:   "None",
			ContainerName: "Image Configuration",
			Threats:       tlist,
		}

		s.VulnContainers = append(s.VulnContainers, ct)
	}

	return nil
}

func checkPrivileged(config *types.ContainerJSON) (bool, []*threat) {
	log.Printf(_config.Yellow("Begin privileged and capabilities analyzing"))

	var vuln = false
	var capList string

	tlist := []*threat{}

	for _, capadd := range config.HostConfig.CapAdd {
		for _, c := range dangerCaps {
			if capadd == c {
				capList += capadd + " "
				vuln = true
			}
		}

		if capadd == "CAP_DAC_READ_SEARCH" {
			th := &threat{
				Param:    "CapAdd",
				Value:    "CAP_DAC_READ_SEARCH",
				Describe: "There has a potential arbitrary file leakage.",
				Severity: "medium",
			}
			tlist = append(tlist, th)
		}
	}
	if vuln {
		th := &threat{
			Param:    "CapAdd",
			Value:    capList,
			Describe: "There has a potential container escape in privileged module.",
			Severity: "critical",
		}
		tlist = append(tlist, th)
	}

	if config.HostConfig.Privileged {
		th := &threat{
			Param:    "Privileged",
			Value:    "true",
			Describe: "There has a potential container escape in privileged module.",
			Severity: "critical",
		}
		tlist = append(tlist, th)
		vuln = true
	}

	return vuln, tlist
}

func checkMount(config *types.ContainerJSON) (bool, []*threat) {
	log.Printf(_config.Yellow("Begin mount analyzing"))

	var vuln = false

	mounts := config.Mounts
	tlist := []*threat{}

	for _, mount := range mounts {

		if isVuln := checkMountPath(mount.Source); isVuln {
			th := &threat{
				Param: "Mount",
				Value: mount.Source,
				Describe: fmt.Sprintf("Mount '%s' in '%s' is suffer vulnerable of "+
					"container escape.", mount.Source, mount.Destination),
				Severity: "critical",
			}
			tlist = append(tlist, th)
			vuln = true
		}

	}
	return vuln, tlist
}

func checkEnvPassword(config *types.ContainerJSON) (bool, []*threat) {
	var vuln = false
	var password string

	tlist := []*threat{}
	imageVersion := config.Config.Image

	// Check weakness password
	if strings.Contains(imageVersion, "mysql") ||
		strings.Contains(imageVersion, "postgres") {

		mysqlReg := regexp.MustCompile(`MYSQL_ROOT_PASSWORD=(.*)`)
		postgReqs := regexp.MustCompile(`POSTGRES_PASSWORD=(.*)`)

		env := config.Config.Env
		for _, e := range env {
			mysqlPass := mysqlReg.FindStringSubmatch(e)
			postPass := postgReqs.FindStringSubmatch(e)
			if len(mysqlPass) > 1 {
				password = mysqlPass[1]
			} else if len(postPass) > 1 {
				password = postPass[1]
			} else {
				continue
			}

			switch checkWeakPassword(password) {
			case "Weak":
				th := &threat{
					Param:    "Weak Password",
					Value:    fmt.Sprintf("Password: '%s'", password),
					Describe: fmt.Sprintf("%s has weak password: '%s'.", imageVersion, password),
					Severity: "high",
				}
				tlist = append(tlist, th)
				vuln = true
			case "Medium":
				th := &threat{
					Param: "Password need to be reinforced",
					Value: fmt.Sprintf("Password: '%s'", password),
					Describe: fmt.Sprintf("%s password '%s' "+
						"need to be reinforced.", imageVersion, password),
					Severity: "low",
				}
				tlist = append(tlist, th)
				vuln = true
			}
		}

	} else if strings.Contains(imageVersion, "redis") {
		args := config.Args

		requirepass := false
		for _, arg := range args {

			if strings.Contains(arg, "--requirepass") {
				requirepass = true
			}

			if requirepass {
				password := arg
				switch checkWeakPassword(password) {
				case "Weak":
					th := &threat{
						Param:    "Weak Password",
						Value:    fmt.Sprintf("Password: '%s'", password),
						Describe: fmt.Sprintf("Redis has weak password: '%s'.", password),
						Severity: "high",
					}
					tlist = append(tlist, th)
					vuln = true
				case "Medium":
					th := &threat{
						Param: "Password need to be reinforced",
						Value: fmt.Sprintf("Password: '%s'", password),
						Describe: fmt.Sprintf("Redis password '%s' "+
							"need to be reinforced.", password),
						Severity: "medium",
					}
					tlist = append(tlist, th)
					vuln = true
				}
			}

		}
	}

	return vuln, tlist
}

// checkNetworkModel check container network model
//reference: https://github.com/containerd/containerd/security/advisories/GHSA-36xw-fx78-c5r4
func checkNetworkModel(config *types.ContainerJSON, version string) (bool, []*threat) {
	var vuln = false

	tlist := []*threat{}

	if config.HostConfig.NetworkMode == "host" {
		currentVersion, _ := version2.NewVersion(version)
		maxVersion, _ := version2.NewVersion("1.3.7")

		if currentVersion.Compare(maxVersion) <= 0 || version == "1.4.1" || version == "1.4.0" {
			th := &threat{
				Param: "network",
				Value: "host",
				Describe: fmt.Sprintf("Containerd version is %s lower than 1.3.7 or 1.4.1"+
					" is suffer vulnerable of CVE-2020-15257.", version),
				Reference: "https://github.com/containerd/containerd/security/advisories/GHSA-36xw-fx78-c5r4",
				Severity:  "critical",
			}
			tlist = append(tlist, th)
			vuln = true
		}
	}

	return vuln, tlist
}

func checkDockerUnauthorized() (bool, []*threat) {
	log.Printf(_config.Yellow("Begin unauthorized analyzing"))

	var vuln = false

	tlist := []*threat{}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	var request *http.Request

	request, err := http.NewRequest("GET", "http://0.0.0.0:2375/info", nil)
	if err != nil {
		return vuln, tlist
	}

	resp, err := client.Do(request)

	if err != nil {
		return vuln, tlist
	}

	defer resp.Body.Close()

	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return vuln, tlist
	}

	value := gjson.Parse(string(content))

	if value.Get("Containers").Value() != nil {
		th := &threat{
			Param:     "Docker unauthorized",
			Value:     "0.0.0.0:2375",
			Describe:  "Exporting 2375 port is suffering the container escape.",
			Reference: "Delete row which contained `tcp://0.0.0.0:2375`.",
			Severity:  "critical",
		}

		tlist = append(tlist, th)
		vuln = true
	}

	return vuln, tlist
}

func checkImages(images []*_image.ImageInfo) (bool, []*threat) {
	log.Printf(_config.Yellow("Begin image analyzing"))

	var vuln = false
	tlist := []*threat{}

	for _, image := range images {
		if len(image.Summary.RepoTags) < 1 {
			sha := strings.Split(image.Summary.ID, ":")[1]
			th := &threat{
				Param:    "Image ID",
				Value:    sha[:12],
				Describe: fmt.Sprintf("Image Id %s is not tagged, suspectable image.", sha[:12]),
				Severity: "low",
			}
			tlist = append(tlist, th)
			vuln = true
			continue
		}

		repoTag := strings.Split(image.Summary.RepoTags[0], ":")
		if len(repoTag) > 1 && repoTag[1] == "latest" {
			th := &threat{
				Param:    "Image Name",
				Value:    image.Summary.RepoTags[0],
				Describe: "Using the latest tag will be suffered potential image hijack.",
				Severity: "low",
			}
			tlist = append(tlist, th)
			vuln = true
		}

	}

	return vuln, tlist
}

func checkHistories(images []*_image.ImageInfo) (bool, []*threat) {
	log.Printf(_config.Yellow("Begin image histories analyzing"))

	var vuln = false
	tlist := []*threat{}

	echoReg := regexp.MustCompile(`echo ["|'](.*?)["|']`)

	for _, img := range images {
		for _, layer := range img.History {
			pruneLayerAfter1 := strings.TrimPrefix(layer.CreatedBy, "/bin/sh -c ")
			pruneLayerAfter2 := strings.TrimPrefix(pruneLayerAfter1, "#(nop)")
			pruneLayer := strings.TrimSpace(pruneLayerAfter2)

			link := strings.Split(pruneLayer, " ")[0]
			switch link {
			case "CMD", "ADD", "ARG", "ENV", "LABEL", "WORKDIR", "COPY", "EXPOSE", "ENTRYPOINT", "USER":
				continue
			}

			commands := strings.Split(pruneLayer, "&&")
			for _, cmd := range commands {
				echoMatch := echoReg.FindStringSubmatch(cmd)
				if len(echoMatch) > 1 {
					pass := echoPass(echoMatch[1])
					if len(pass) < 1 {
						continue
					}

					switch checkWeakPassword(pass) {
					case "Weak":
						th := &threat{
							Param: "Image History",
							Value: fmt.Sprintf("Image name: %s \n "+
								"Image ID: %s", img.Summary.RepoTags[0],
								strings.TrimPrefix(img.Summary.ID, "sha256:")[:12]),
							Describe: fmt.Sprintf("Weak password found in command: '%s'.", cmd),
							Severity: "high",
						}

						tlist = append(tlist, th)
						vuln = true

					case "Medium":
						th := &threat{
							Param: "Image History",
							Value: fmt.Sprintf("Image name: %s \n "+
								"Image ID: %s", img.Summary.RepoTags[0],
								strings.TrimPrefix(img.Summary.ID, "sha256:")[:12]),
							Describe: fmt.Sprintf("Password need need to be reinforeced, found in command: '%s'.", cmd),
							Severity: "medium",
						}

						tlist = append(tlist, th)
						vuln = true
					}
				}
			}

		}
	}

	return vuln, tlist
}

func echoPass(cmd string) string {

	var pass string
	match := false

	for _, p := range passKey {
		if p.MatchString(cmd) {
			match = true
			break
		}
	}

	if !match {
		return pass
	}

	prune := strings.TrimSpace(cmd)

	if len(strings.Split(prune, "=")) > 1 {
		pass = strings.Split(prune, "=")[1]
	} else if len(strings.Split(prune, ":")) > 1 {
		pass = strings.Split(prune, ":")[1]
	}

	pass = strings.TrimSpace(pass)

	return pass
}
