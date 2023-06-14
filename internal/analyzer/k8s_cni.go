package analyzer

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/kvesta/vesta/config"
	"github.com/kvesta/vesta/pkg/vulnlib"
	"github.com/shirou/gopsutil/process"
	"github.com/tidwall/gjson"
	"gopkg.in/yaml.v3"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/remotecommand"
)

func (ks *KScanner) checkCNI() error {

	// Init database
	vulnCli := vulnlib.Client{}
	err := vulnCli.Init()
	if err != nil {
		log.Printf("init database failed, %v", err)
	}

	// Check Envoy configuration
	if ok, tlist := checkEnvoy(); ok {
		ks.VulnConfigures = append(ks.VulnConfigures, tlist...)
	}

	// Check cilium
	if ok, tlist := ks.checkCilium(vulnCli); ok {
		ks.VulnConfigures = append(ks.VulnConfigures, tlist...)
	}

	// Check istio
	if ok, tlist := ks.checkIstio(vulnCli); ok {
		ks.VulnConfigures = append(ks.VulnConfigures, tlist...)
	}

	// Check kubelet port
	if ok, tlist := ks.checkKubelet(); ok {
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
	log.Printf(config.Yellow("Begin Envoy analyzing"))

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
				Value: fmt.Sprintf("Pid:%d  Command: \"%s\"", ps.Pid, envoyCommand),
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

func (ks *KScanner) checkIstio(vulnCli vulnlib.Client) (bool, []*threat) {
	log.Printf(config.Yellow("Begin Istio analyzing"))

	var vuln = false
	tlist := []*threat{}

	// Get istio deployment
	dp, err := ks.KClient.
		AppsV1().
		Deployments("istio-system").
		Get(context.Background(), "istiod", metav1.GetOptions{})
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return vuln, tlist
		}

		log.Printf("check istio version failed, %v", err)
		return vuln, tlist
	}

	if dp == nil {
		return vuln, tlist
	}

	// Check istio version
	imageName := dp.Spec.Template.Spec.Containers[0].Image
	versionRegex := regexp.MustCompile(`(\d+\.)?(\d+\.)?(\*|\d+)$`)
	versionMatch := versionRegex.FindStringSubmatch(imageName)
	if len(versionMatch) < 2 {
		return vuln, tlist
	}

	istioVersion := versionMatch[0]

	rows, err := vulnCli.QueryVulnByName("istio")
	if err != nil {
		log.Printf("check envoy version failed, %v", err)
		return vuln, tlist
	}

	for _, row := range rows {
		if compareVersion(istioVersion, row.MaxVersion, row.MinVersion) {
			var description string
			if len(row.Description) > 100 {
				description = fmt.Sprintf("%s ... Reference: %s", row.Description[:100], row.CVEID)
			} else {
				description = fmt.Sprintf("%s ... Reference: %s", row.Description, row.CVEID)
			}

			th := &threat{
				Param:     "Istio version",
				Value:     istioVersion,
				Type:      "Istio",
				Describe:  description,
				Reference: fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", row.CVEID),
				Severity:  strings.ToLower(row.Level),
			}

			tlist = append(tlist, th)
			vuln = true
		}
	}

	return vuln, tlist
}

func (ks *KScanner) checkIstioHeader(podname, ns, cname string) (bool, []*threat) {
	var vuln = false
	tlist := []*threat{}

	cmd := []string{
		"curl",
		"http://httpbin.org/get",
	}

	req := ks.KClient.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(podname).
		Namespace(ns).SubResource("exec").Param("container", cname)
	option := &v1.PodExecOptions{
		Command: cmd,
		Stdin:   false,
		Stdout:  true,
		Stderr:  true,
		TTY:     false,
	}
	req.VersionedParams(
		option,
		scheme.ParameterCodec,
	)

	var stdout, stderr bytes.Buffer

	exec, err := remotecommand.NewSPDYExecutor(ks.KConfig, "POST", req.URL())
	if err != nil {
		return vuln, tlist
	}

	err = exec.Stream(remotecommand.StreamOptions{
		Stdin:  nil,
		Stdout: &stdout,
		Stderr: &stderr,
	})

	if err != nil {
		return vuln, tlist
	}

	data := strings.TrimSpace(stdout.String())
	headers := gjson.Get(data, "headers").Value()
	if headers == nil {
		return vuln, tlist
	}

	if _, ok := headers.(map[string]interface{})["X-Envoy-Peer-Metadata"]; ok {
		th := &threat{
			Param: "istio header",
			Value: "X-Envoy-Peer-Metadata, X-Envoy-Peer-Metadata-Id",
			Type:  "Istio",
			Describe: "Istio detected and request header " +
				"is leaking sensitive information",
			Reference: "https://github.com/istio/istio/issues/17635",
			Severity:  "low",
		}

		tlist = append(tlist, th)
		vuln = true
	}

	return vuln, tlist
}

func (ks *KScanner) checkCilium(vulnCli vulnlib.Client) (bool, []*threat) {
	log.Printf(config.Yellow("Begin cilium analyzing"))

	var vuln = false
	tlist := []*threat{}

	// Get cilium deployment
	dp, err := ks.KClient.
		AppsV1().
		Deployments("kube-system").
		Get(context.Background(), "cilium-operator", metav1.GetOptions{})
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return vuln, tlist
		}

		log.Printf("check envoy version failed, %v", err)
		return vuln, tlist
	}

	if dp == nil {
		return vuln, tlist
	}

	// Check cilium version
	imageName := dp.Spec.Template.Spec.Containers[0].Image
	imageRegexp := regexp.MustCompile(`\A(.*?)(?:(:.*?)(@sha256:[0-9a-f]{64})?)?\z`)
	versionMatch := imageRegexp.FindStringSubmatch(imageName)
	if len(versionMatch) < 2 {
		return vuln, tlist
	}

	ciliumVersion := versionMatch[2][1:]
	rows, err := vulnCli.QueryVulnByName("cilium")
	if err != nil {
		log.Printf("check envoy version failed, %v", err)
		return vuln, tlist
	}

	for _, row := range rows {
		if compareVersion(ciliumVersion, row.MaxVersion, row.MinVersion) {
			var description string
			if len(row.Description) > 200 {
				description = fmt.Sprintf("%s ... Reference: %s", row.Description[:100], row.CVEID)
			} else {
				description = fmt.Sprintf("%s ... Reference: %s", row.Description[:100], row.CVEID)
			}

			th := &threat{
				Param:     "Cilium version",
				Value:     ciliumVersion,
				Type:      "Cilium",
				Describe:  description,
				Reference: fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", row.CVEID),
				Severity:  strings.ToLower(row.Level),
			}

			tlist = append(tlist, th)
			vuln = true
		}
	}

	return vuln, tlist
}

func (ks *KScanner) checkKubelet() (bool, []*threat) {
	log.Printf(config.Yellow("Begin Kubelet analyzing"))

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

	// Check 10250 and 10255 unauthorized
	for nodeName, node := range ks.MasterNodes {
		if ok, ts := checkKubeletUnauthorized(node.InternalIP); ok {
			for _, t := range ts {
				t.Param += fmt.Sprintf(" | Node Name: '%s' | Node Interal IP: %s", nodeName, node.InternalIP)
			}

			vuln = true
			tlist = append(tlist, ts...)
		}

	}

	return vuln, tlist
}

func checkKubeletUnauthorized(ip string) (bool, []*threat) {

	var vuln = false
	tlist := []*threat{}

	ports := []int{10255, 10250}

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	for _, port := range ports {
		url := fmt.Sprintf("https://%s:%d/pods/", ip, port)
		request, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}

		resp, err := client.Do(request)

		if err != nil {
			continue
		}

		content, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			continue
		}

		if len(content) > 100 && strings.Contains(string(content), "apiVersion") {
			th := &threat{
				Param: fmt.Sprintf("Kubelet port: '%d' unauthorized", port),
				Value: fmt.Sprintf("Unauthorized, check the url: %s", url),
				Type:  "Kubelet",
				Describe: fmt.Sprintf("Kubelet port: '%d' unauthorized, "+
					"which leak all the information to the anonymous.", port),
				Severity: "high",
			}

			vuln = true
			tlist = append(tlist, th)
		}

		resp.Body.Close()
	}

	return vuln, tlist
}

func checkKubectlProxy() (bool, []*threat) {
	log.Printf(config.Yellow("Begin Kubectl proxy analyzing"))

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

func (ks *KScanner) checkEtcd() (bool, []*threat) {
	log.Printf(config.Yellow("Begin Etcd analyzing"))

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
