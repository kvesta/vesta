package analyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/kvesta/vesta/pkg/vulnlib"
	"github.com/shirou/gopsutil/process"
	"gopkg.in/yaml.v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (ks *KScanner) checkCNI() error {

	// Check Envoy configuration
	if ok, tlist := checkEnvoy(); ok {
		ks.VulnConfigures = append(ks.VulnConfigures, tlist...)
	}

	// Check cilium
	if ok, tlist := ks.checkCilium(); ok {
		ks.VulnConfigures = append(ks.VulnConfigures, tlist...)
	}

	// Check kubelet port
	if ok, tlist := checkKubelet(); ok {
		ks.VulnConfigures = append(ks.VulnConfigures, tlist...)
	}

	// Check kubectl proxy using
	if ok, tlist := checkKubectlProxy(); ok {
		ks.VulnConfigures = append(ks.VulnConfigures, tlist...)
	}

	// Check etcd configuration
	if ok, tlist := ks.checkEtcd(); ok {
		ks.VulnConfigures = append(ks.VulnConfigures, tlist...)
	}

	return nil
}

func checkEnvoy() (bool, []*threat) {

	var vuln = false
	tlist := []*threat{}

	type envoyAdmin struct {
		Admin struct {
			Address struct {
				SocketAddress struct {
					Address   string `yaml:"address" json:"address"`
					PortValue string `yaml:"port_value" json:"port_value"`
				} `yaml:"socket_address" json:"socket_address"`
			} `yaml:"address" json:"address"`
		} `yaml:"admin" json:"admin"`
	}

	// Only supports Linux
	if runtime.GOOS != "linux" {
		return vuln, tlist
	}

	var filename string
	var envoyConfig envoyAdmin

	// Check process or docker to find envoy
	processes, _ := process.Processes()
	for _, ps := range processes {
		cmds, _ := ps.CmdlineSlice()
		if len(cmds) < 1 {
			continue
		}

		if !strings.Contains(cmds[0], "envoy") {
			continue
		}

		cwd := fmt.Sprintf("/proc/%d/cwd/", ps.Pid)

		// Get the name of config file
		for i, p := range cmds {
			if p == "-c" {
				filename = cmds[i+1]
				break
			}
		}

		configFile := filepath.Join(cwd, filename)

		// Judge file type
		fileSplit := strings.Split(configFile, ".")
		fileType := fileSplit[len(fileSplit)-1]

		f, err := os.Open(configFile)
		if err != nil {
			continue
		}

		config, err := io.ReadAll(f)
		if err != nil {
			f.Close()
			continue
		}

		f.Close()

		switch fileType {
		case "yaml":
			err = yaml.Unmarshal(config, &envoyConfig)
			if err != nil {
				continue
			}

		case "json":
			err = json.Unmarshal(config, &envoyConfig)
			if err != nil {
				continue
			}

		default:
			continue

		}

		if envoyConfig != (envoyAdmin{}) {

			address := envoyConfig.Admin.Address.SocketAddress.Address
			port := envoyConfig.Admin.Address.SocketAddress.PortValue

			envoyCommand := strings.Join(cmds[1:], " ")
			if len(envoyCommand) > 80 {
				envoyCommand = "envoy " + envoyCommand[:80] + "..."
			} else {
				envoyCommand = strings.Join(cmds, " ")
			}

			th := &threat{
				Param: "admin",
				Value: fmt.Sprintf("Pid:%d \nCommand:\n \"%s\"", ps.Pid, envoyCommand),
				Type:  "Envoy",
				Describe: fmt.Sprintf("Envoy admin is activated and exposed to '%s:%s', "+
					"which includes sensitive api and unauthorized.", address, port),
				Reference: "https://www.envoyproxy.io/docs/envoy/latest/operations/admin#administration-interface",
				Severity:  "medium",
			}

			if address == "0.0.0.0" {
				th.Severity = "high"
			}

			tlist = append(tlist, th)
			vuln = true
		}

	}

	return vuln, tlist
}

func (ks KScanner) checkIstio() error {
	return nil
}

func (ks KScanner) checkCilium() (bool, []*threat) {

	var vuln = false
	tlist := []*threat{}

	// Init database
	vulnCli := vulnlib.Client{}
	err := vulnCli.Init()
	if err != nil {
		log.Printf("check envoy configuration failed, %v", err)
		return vuln, tlist
	}

	// Get cilium deployment
	dp, err := ks.KClient.AppsV1().Deployments("kube-system").Get(context.Background(), "cilium-operator", metav1.GetOptions{})
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return vuln, tlist
		}

		log.Printf("check envoy configuration failed, %v", err)
		return vuln, tlist
	}

	if dp == nil {
		return vuln, tlist
	}

	// Check cilium version
	imageName := dp.Spec.Template.Spec.Containers[0].Image
	imageRegexp := regexp.MustCompile(`\A(.*?)(?:(:.*?)(@sha256:[0-9a-f]{64})?)?\z`)
	versionMatch := imageRegexp.FindStringSubmatch(imageName)
	ciliumVersion := versionMatch[2][1:]
	rows, err := vulnCli.QueryVulnByCVEID("CVE-2022-29179")
	if err != nil {
		log.Printf("check envoy configuration failed, %v", err)
		return vuln, tlist
	}

	for _, row := range rows {
		if compareVersion(ciliumVersion, row.MaxVersion, row.MinVersion) {
			th := &threat{
				Param: "Cilium version",
				Value: ciliumVersion,
				Type:  "Cilium",
				Describe: "Prior to versions 1.9.16, 1.10.11, and 1.11.15, " +
					"If an attacker is able to perform a container escape of a container " +
					"running as root on a host where Cilium is installed," +
					"the attacker can escalate privileges to cluster admin " +
					"by using Cilium's Kubernetes service account.",
				Reference: "https://nvd.nist.gov/vuln/detail/CVE-2022-29179",
				Severity:  "high",
			}

			tlist = append(tlist, th)
			vuln = true
		}
	}

	return vuln, tlist
}

func checkKubelet() (bool, []*threat) {
	var vuln = false
	tlist := []*threat{}

	// Only supports Linux
	if runtime.GOOS != "linux" {
		return vuln, tlist
	}

	processes, _ := process.Processes()
	for _, ps := range processes {
		cmds, _ := ps.CmdlineSlice()
		if len(cmds) < 1 {
			continue
		}

		if !strings.Contains(cmds[0], "kubelet") {
			continue
		}

		for _, cmd := range cmds {
			if strings.Contains(cmd, "--read-only-port=") {

				th := &threat{
					Param: "Kubelet 'read-only-port' is opened",
					Value: cmd,
					Type:  "Kubelet",
					Describe: "Kubelet 'read-only-port' is opened and unauthorized, " +
						"which has a sensitive data leakage.",
					Severity: "high",
				}

				tlist = append(tlist, th)
				vuln = true
			}
		}

	}

	return vuln, tlist
}

func checkKubectlProxy() (bool, []*threat) {
	var vuln = false
	tlist := []*threat{}

	processes, _ := process.Processes()
	for _, ps := range processes {
		cmds, _ := ps.CmdlineSlice()
		if len(cmds) < 1 {
			continue
		}

		if !strings.Contains(cmds[0], "kubectl") {
			continue
		}

		// Skip the kuebctl command which is not includes proxy
		if cmds[1] != "proxy" {
			continue
		}

		kubectlCommand := strings.Join(cmds[2:], " ")
		if len(kubectlCommand) > 50 {
			kubectlCommand = "kubectl proxy " + kubectlCommand[:50] + "..."
		} else {
			kubectlCommand = strings.Join(cmds[:], " ")
		}

		for i, cmd := range cmds {
			if strings.Contains(cmd, "--address") {
				var address string
				if strings.Contains(cmd, "=") {
					address = strings.Split(cmd, "=")[1]
				} else {
					address = cmds[i+1]
				}

				if address == "localhost" || address == "127.0.0.1" {
					break
				}

				th := &threat{
					Param: "Kubectl proxy",
					Value: kubectlCommand,
					Type:  "Kubectl",
					Describe: fmt.Sprintf("Kubectl proxy command is used "+
						"and the exposed address is '%s', "+
						"which will cause unauthorized vulnerability.", address),
					Severity: "medium",
				}
				tlist = append(tlist, th)
				vuln = true

			}
		}

		if !vuln {
			th := &threat{
				Param: "Kubectl proxy",
				Value: kubectlCommand,
				Type:  "Kubectl",
				Describe: "Kubectl proxy command is used " +
					"which will cause unauthorized vulnerability.",
				Severity: "low",
			}

			tlist = append(tlist, th)
			vuln = true
		}

	}

	return vuln, tlist
}

func (ks KScanner) checkEtcd() (bool, []*threat) {
	var vuln = false
	tlist := []*threat{}

	pods, err := ks.KClient.CoreV1().Pods("kube-system").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return vuln, tlist
	}

	configs := map[string]bool{"client-cert-auth": false,
		"peer-client-cert-auth": false}

	for _, pod := range pods.Items {
		if !strings.Contains(pod.Name, "etcd") {
			continue
		}

		commands := pod.Spec.Containers[0].Command
		for _, command := range commands {
			if command == "--client-cert-auth=true" {
				configs["client-cert-auth"] = true
			}

			if command == "--peer-client-cert-auth=true" {
				configs["peer-client-cert-auth"] = true
			}
		}

	}

	if !configs["client-cert-auth"] {

		th := &threat{
			Param: "Etcd configuration",
			Value: "--client-cert-auth",
			Type:  "Etcd",
			Describe: "Etcd config lacks `client-cert-auth`, " +
				"which has a potential container escape.",
			Severity: "high",
		}

		if !configs["peer-client-cert-auth"] {
			th.Value += " --peer-client-cert-auth"
			th.Describe = "Etcd config lacks `client-cert-auth` " +
				"and `peer-client-cert-auth`, which has a potential container escape."
			th.Reference = "https://workbench.cisecurity.org/files/3371"
		}

		tlist = append(tlist, th)
		vuln = true
	} else if !configs["peer-client-cert-auth"] {
		th := &threat{
			Param: "Etcd configuration",
			Value: "--peer-client-cert-auth",
			Type:  "Etcd",
			Describe: "Etcd config lacks `peer-client-cert-auth`. " +
				"All peers attempting to communicate with the etcd server " +
				"will require a valid client certificate for authentication.",
			Reference: "https://workbench.cisecurity.org/files/3371",
			Severity:  "medium",
		}

		tlist = append(tlist, th)
		vuln = true
	}

	return vuln, tlist
}
