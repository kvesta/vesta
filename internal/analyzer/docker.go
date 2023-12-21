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
	"github.com/kvesta/vesta/pkg/osrelease"
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
	kernelVersion, err := osrelease.GetKernelVersion(context.Background())
	if err != nil {
		log.Printf("failed to get kernel version: %v", err)
	}

	// Checking the docker swarm
	err = s.checkSwarm()
	if err != nil {
		log.Printf("docker swarm error: %v", err)
	}

	if ok, tlist := checkKernelVersion(cli, kernelVersion); ok {
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
	// We found that it is hard to exploit
	/*
		if ok, tlist := checkImages(images); ok {
			ct := &container{
				ContainerID:   "None",
				ContainerName: "Image Tag",
				Threats:       tlist,
			}

			s.VulnContainers = append(s.VulnContainers, ct)
		}
	*/

	// Check image's history
	if ok, tlist := CheckHistories(images); ok {
		ct := &container{
			ContainerID:   "None",
			ContainerName: "Image Configuration",
			Threats:       tlist,
		}

		s.VulnContainers = append(s.VulnContainers, ct)
	}

	return nil
}

func checkSwarmLabels(labels map[string]string, name, configType string) (bool, []*threat) {
	var vuln = false
	tlist := []*threat{}

	match := false

	for k, v := range labels {
		for _, p := range passKey {
			if p.MatchString(k) {
				match = true
				break
			}
		}

		if match {
			switch checkWeakPassword(v) {
			case "Weak":
				th := &threat{
					Param:    configType + " Label",
					Value:    fmt.Sprintf("%s name: %s", configType, name),
					Describe: fmt.Sprintf("Lables '%s' has weak password: '%s'.", k, v),
					Severity: "high",
				}

				tlist = append(tlist, th)
				vuln = true
			case "Medium":
				th := &threat{
					Param: configType + " Label",
					Value: fmt.Sprintf("%s name: %s", configType, name),
					Describe: fmt.Sprintf("Lables '%s' password '%s' "+
						"need to be reinforced.", k, v),
					Severity: "low",
				}

				tlist = append(tlist, th)
				vuln = true
			}
		}
	}

	return vuln, tlist
}

func (s *Scanner) checkSwarmSecrets() error {
	var vuln = false
	tlist := []*threat{}

	ses, err := s.DApi.
		DCli.
		SecretList(context.Background(), types.SecretListOptions{})

	if err != nil {
		log.Printf("failed to check docker config")
		return err
	}

	// TODO: check the content of the secret

	for _, se := range ses {
		vuln, tlist = checkSwarmLabels(se.Spec.Labels, se.Spec.Name, "Secret")
	}

	if vuln {
		ct := &container{
			ContainerID:   "None",
			ContainerName: "Docker Swarm Secret",
			Threats:       tlist,
		}

		s.VulnContainers = append(s.VulnContainers, ct)
	}

	return nil
}

func (s *Scanner) checkSwarmConfigs() error {

	var vuln = false
	tlist := []*threat{}

	cons, err := s.DApi.
		DCli.
		ConfigList(context.Background(), types.ConfigListOptions{})

	if err != nil {
		return err
	}

	for _, con := range cons {
		configData := string(con.Spec.Data)
		detect := maliciousContentCheck(configData)
		switch detect.Types {
		case Executable:
			th := &threat{
				Param: "Config Data",
				Value: fmt.Sprintf("Config name: %s", con.Spec.Name),
				Describe: fmt.Sprintf("Malicious value found in config Data "+
					"with the plain text '%s'.", detect.Plain),
				Severity: "high",
			}

			tlist = append(tlist, th)
			vuln = true

		case Confusion:
			th := &threat{
				Param: "Config Data",
				Value: fmt.Sprintf("Config name: %s", con.Spec.Name),
				Describe: fmt.Sprintf("Confusion value found in config Data "+
					"with the plain text '%s'.", detect.Plain),
				Severity: "high",
			}

			tlist = append(tlist, th)
			vuln = true

		default:
			// ignore
		}

		vulnLabel, tlistLabel := checkSwarmLabels(con.Spec.Labels, con.Spec.Name, "Config")

		if vulnLabel {
			vuln = true
			tlist = append(tlist, tlistLabel...)
		}

	}

	if vuln {
		ct := &container{
			ContainerID:   "None",
			ContainerName: "Docker Swarm Config",
			Threats:       tlist,
		}

		s.VulnContainers = append(s.VulnContainers, ct)
	}

	return nil
}

func (s *Scanner) checkDockerService() error {

	var vuln = false
	tlist := []*threat{}

	sers, err := s.DApi.
		DCli.
		ServiceList(context.Background(), types.ServiceListOptions{})
	if err != nil {
		return err
	}

	for _, se := range sers {
		// Checking the swarm config
		for _, c := range se.Spec.TaskTemplate.ContainerSpec.Configs {
			for _, v := range s.VulnContainers {
				if strings.Contains(v.ContainerName, "Docker Swarm Config") {
					for _, t := range v.Threats {
						if strings.HasSuffix(t.Value, c.ConfigName) {
							th := &threat{
								Param:    "Swarm Service",
								Value:    fmt.Sprintf("Service Name: %s", se.Spec.Name),
								Describe: fmt.Sprintf("Docker Service is using the unsafe swarm config: '%s'.", c.ConfigName),
								Severity: t.Severity,
							}

							tlist = append(tlist, th)
							vuln = true

							break
						}

					}
				}

			}
		}

		// Checking the swarm secret
		for _, secret := range se.Spec.TaskTemplate.ContainerSpec.Secrets {
			for _, v := range s.VulnContainers {
				if strings.Contains(v.ContainerName, "Docker Swarm Secret") {
					for _, t := range v.Threats {
						if strings.HasSuffix(t.Value, secret.File.Name) {
							th := &threat{
								Param:    "Swarm Service",
								Value:    fmt.Sprintf("Service Name: %s", se.Spec.Name),
								Describe: fmt.Sprintf("Docker Service is using the unsafe swarm secret: '%s'.", secret.File.Name),
								Severity: t.Severity,
							}

							tlist = append(tlist, th)
							vuln = true

							break
						}
					}
				}
			}
		}
	}

	if vuln {
		ct := &container{
			ContainerID:   "None",
			ContainerName: "Docker Swarm Service",
			Threats:       tlist,
		}

		s.VulnContainers = append(s.VulnContainers, ct)
	}

	return nil
}

func (s *Scanner) checkSwarm() error {

	_, err := s.DApi.
		DCli.
		ServiceList(context.Background(), types.ServiceListOptions{})
	if err != nil {
		if strings.Contains(err.Error(), "This node is not a swarm manager") {
			return nil
		}

		return err
	}

	log.Printf(_config.Yellow("Begin docker swarm analyzing"))

	err = s.checkSwarmConfigs()

	err = s.checkSwarmSecrets()

	err = s.checkDockerService()
	if err != nil {
		log.Printf("failed to check docker service")
	}

	return err
}

func checkPrivileged(config *types.ContainerJSON) (bool, []*threat) {

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

		if !vuln {
			th := &threat{
				Param: "network",
				Value: "host",
				Describe: "Docker container is running with `--net=host`, " +
					"which will exposed the network of physical machine.",
				Severity: "medium",
			}

			tlist = append(tlist, th)
			vuln = true
		}
	}

	return vuln, tlist
}

func checkPid(config *types.ContainerJSON) (bool, []*threat) {
	var vuln = false

	tlist := []*threat{}

	if config.HostConfig.PidMode == "host" {
		th := &threat{
			Param: "pid",
			Value: "host",
			Describe: "Docker container is run with `--pid=host`, " +
				"which attackers can see all the processes in physical machine" +
				" and cause the potential container escape.",
			Severity: "high",
		}

		tlist = append(tlist, th)
		vuln = true
	}

	return vuln, tlist
}

func checkImageUsed(config *types.ContainerJSON, vulnContainers []*container) (bool, []*threat) {
	var vuln = false

	tlist := []*threat{}

	imageMixed := strings.Split(config.Image, ":")
	imageID := imageMixed[1][:12]
	for _, v := range vulnContainers {
		if strings.Contains(v.ContainerName, "Image Configuration") {
			for _, ids := range v.Threats {
				if strings.Contains(ids.Value, imageID) {
					th := &threat{
						Param:    "Dangerous image",
						Value:    fmt.Sprintf("Image ID: %s", imageID),
						Describe: "Docker container used dangerous image.",
						Severity: ids.Severity,
					}

					tlist = append(tlist, th)
					vuln = true

					break
				}
			}
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
