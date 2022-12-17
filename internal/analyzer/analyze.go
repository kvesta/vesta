package analyzer

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"strings"

	"github.com/kvesta/vesta/pkg/osrelease"
	"github.com/kvesta/vesta/pkg/vulnlib"

	"github.com/docker/docker/api/types"
	version2 "github.com/hashicorp/go-version"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var dangerPrefixMountPaths = []string{"/etc/crontab", "/private/etc",
	"/var/run", "/run/containerd", "/sys/fs/cgroup", "/root/.ssh"}

var dangerFullPaths = []string{"/", "/etc", "/proc", "/sys", "/root"}

var namespaceWhileList = []string{"istio-system", "kube-system", "kube-public",
	"kubesphere-router-gateway", "kubesphere-system"}

func (s *Scanner) Analyze(ctx context.Context, inspectors []*types.ContainerJSON, images []types.ImageSummary) error {

	err := s.checkDockerContext(ctx, images)
	if err != nil {
		log.Printf("failed to check docker context, error: %v", err)
	}

	for _, in := range inspectors {
		err := s.checkDockerList(in)
		if err != nil {
			log.Printf("Container %s check error, %v", in.ID[:12], err)
		}
	}
	return nil
}

func (ks *KScanner) Kanalyze(ctx context.Context) error {

	err := ks.checkKubernetesList(ctx)
	if err != nil {
		return err
	}

	return nil
}

func (s *Scanner) checkDockerList(config *types.ContainerJSON) error {

	var isVulnerable = false
	ths := []*threat{}

	// Checking privileged
	if ok, tlist := checkPrivileged(config); ok {
		ths = append(ths, tlist...)
		isVulnerable = true
	}

	// Checking mount volumes
	if ok, tlist := checkMount(config); ok {
		ths = append(ths, tlist...)
		isVulnerable = true
	}

	// Check the strength of password
	if ok, tlist := checkEnvPassword(config); ok {
		ths = append(ths, tlist...)
		isVulnerable = true
	}

	// Checking network model
	if ok, tlist := checkNetworkModel(config, s.EngineVersion); ok {
		ths = append(ths, tlist...)
		isVulnerable = true
	}

	if isVulnerable {
		sortSeverity(ths)

		con := &container{
			ContainerID:   config.ID[:12],
			ContainerName: config.Name[1:],

			Threats: ths,
		}
		s.VulnContainers = append(s.VulnContainers, con)
	}

	return nil
}

func (ks *KScanner) checkKubernetesList(ctx context.Context) error {

	version, err := ks.KClient.ServerVersion()

	if err != nil {
		if strings.Contains(err.Error(), "connection refused") {
			log.Printf("kubelet is not start")
		} else {
			log.Printf("failed to start Kubernetes, error: %v", err)
		}
		return err
	}
	ks.Version = version.String()

	// If k8s version less than v1.24, using the docker checking
	if compareVersion(ks.Version, "1.24", "0.0") {
		err = ks.dockershimCheck(ctx)
		if err != nil {
			log.Printf("failed to use docker to check, error: %v", err)
		}
	}

	nsList, err := ks.KClient.CoreV1().Namespaces().List(context.TODO(), metav1.ListOptions{})

	if err != nil {
		log.Printf("Get namespace failed: %v", err)
	}

	// Check pod
	if ctx.Value("nameSpace") != "all" {
		ns := ctx.Value("nameSpace")
		err := ks.checkPod(ns.(string))
		if err != nil {
			log.Printf("check pod failed, %v", err)
		}

		err = ks.checkJobsOrCornJob(ns.(string))
		if err != nil {
			log.Printf("check job failed, %v", err)
		}

		err = ks.checkConfigMap(ns.(string))
		if err != nil {
			log.Printf("check config map failed, %v", err)
		}

		err = ks.checkSecret(ns.(string))
		if err != nil {
			log.Printf("check secret failed, %v", err)
		}

	} else {
		for _, ns := range nsList.Items {

			isNecessary := true

			// Check whether in the white list of namespaces
			for _, nswList := range namespaceWhileList {
				if ns.Name == nswList {
					isNecessary = false
				}
			}

			if isNecessary {
				err := ks.checkPod(ns.Name)
				if err != nil {
					log.Printf("check pod failed, %v", err)
				}

				err = ks.checkJobsOrCornJob(ns.Name)
				if err != nil {
					log.Printf("check job failed, %v", err)
				}

				err = ks.checkConfigMap(ns.Name)
				if err != nil {
					log.Printf("check config map failed, %v", err)
				}

				err = ks.checkSecret(ns.Name)
				if err != nil {
					log.Printf("check secret failed, %v", err)
				}

			}
		}
	}

	// Check PV and PVC
	err = ks.checkPersistentVolume()
	if err != nil {
		log.Printf("check pv and pvc failed, %v", err)
	}

	// Check RBAC rules
	err = ks.checkClusterBinding()
	if err != nil {
		log.Printf("check RBAC failed, %v", err)
	}

	// Check certification expiration
	err = ks.checkCerts()
	if err != nil {
		log.Printf("check certification expiration failed, %v", err)
	}

	// Check envoy configuration
	err = ks.checkEnvoy()
	if err != nil {
		log.Printf("check envoy configuration failed, %v", err)
	}

	sortSeverity(ks.VulnConfigures)

	return nil
}

func compareVersion(currentVersion, maxVersion, minVersion string) bool {
	k1, err := version2.NewVersion(currentVersion)
	if err != nil {
		return false
	}

	if strings.Contains(maxVersion, "=") {
		maxv, _ := version2.NewVersion(maxVersion[1:])
		if strings.Contains(minVersion, "=") {
			minv, _ := version2.NewVersion(minVersion[1:])
			if k1.Compare(maxv) <= 0 && k1.Compare(minv) >= 0 {
				return true
			}
		} else {
			minv, _ := version2.NewVersion(minVersion)
			if k1.Compare(maxv) <= 0 && k1.Compare(minv) > 0 {
				return true
			}
		}

	} else {
		maxv, _ := version2.NewVersion(maxVersion)
		if strings.Contains(minVersion, "=") {
			minv, _ := version2.NewVersion(minVersion[1:])
			if k1.Compare(maxv) < 0 && k1.Compare(minv) >= 0 {

				return true
			}
		} else {
			minv, _ := version2.NewVersion(minVersion)
			if k1.Compare(maxv) < 0 && k1.Compare(minv) > 0 {
				return true
			}
		}
	}
	return false
}

func checkPrefixMountPaths(path string) bool {
	for _, p := range dangerPrefixMountPaths {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

func checkFullPaths(path string) bool {

	for _, p := range dangerFullPaths {
		if path == p {
			return true
		}
	}
	return false
}

func checkMountPath(path string) bool {
	return checkPrefixMountPaths(path) || checkFullPaths(path)
}

// checkDockerVersion check docker server version
func checkDockerVersion(cli vulnlib.Client, serverVersion string) (bool, []*threat) {
	var vuln = false

	tlist := []*threat{}

	rows, err := cli.QueryVulnByName("docker")
	if err != nil {
		return vuln, tlist
	}

	for _, row := range rows {
		if compareVersion(serverVersion, row.MaxVersion, row.MinVersion) {
			th := &threat{
				Param:     "Docker server",
				Value:     serverVersion,
				Type:      "K8s version less than v1.24",
				Describe:  fmt.Sprintf("Docker server version is threated under the %s", row.CVEID),
				Reference: row.Description,
				Severity:  strings.ToLower(row.Level),
			}

			tlist = append(tlist, th)
			vuln = true
		}
	}

	return vuln, tlist
}

// checkKernelVersion check kernel version for whether the kernel version
// is under the vulnerable version which has a potential container escape
// such as Dirty Cow,Dirty Pipe
func checkKernelVersion(cli vulnlib.Client) (bool, []*threat) {
	var vuln = false

	tlist := []*threat{}

	var vulnKernelVersion = map[string]string{
		"CVE-2016-5195": "Dirty Cow",
		"CVE-2022-0847": "Dirty Pipe",
		"CVE-2022-0185": "CVE-2022-0185 with CAP_SYS_ADMIN",
		"CVE-2022-0492": "CVE-2022-0492 with CAP_SYS_ADMIN and v1 architecture of cgroups"}

	kernelVersion, err := osrelease.GetKernelVersion(context.Background())
	if err != nil {
		log.Printf("failed to get kernel version: %v", err)
	}

	if err != nil {
		log.Printf("failed to init database, error %v", err)
		return vuln, tlist
	}

	for cve, nickname := range vulnKernelVersion {
		underVuln := false
		if err != nil {
			log.Printf("failed to recognize kernel version")
			break
		}

		row, err := cli.QueryVulnByCVEID(cve)
		if err != nil {
			log.Printf("faield to search database, error: %v", err)
			break
		}

		// The data of CVE-2016-5195 is not correct
		if cve == "CVE-2016-5195" {
			row.MaxVersion = "4.8.3"
		}

		if compareVersion(kernelVersion, row.MaxVersion, row.MinVersion) {

			vuln, underVuln = true, true
		}

		if underVuln {
			th := &threat{
				Param: "kernel version",
				Value: kernelVersion,
				Type:  "K8s version less than v1.24",
				Describe: fmt.Sprintf("Kernel version is suffering the %s vulnerablility, "+
					"has a potential container escape.", nickname),
				Reference: "Upload kernel version or docker-desktop.",
				Severity:  "critical",
			}

			tlist = append(tlist, th)
		}
	}

	return vuln, tlist
}

func checkWeakPassword(pass string) string {
	countCase := 0

	// Particularly checking the keyword
	keyWords := []string{"password", "admin", "qwerty", "1q2w3e"}
	for _, keyword := range keyWords {
		replmatch := regexp.MustCompile(fmt.Sprintf(`(?i)%s`, keyword))
		pass = replmatch.ReplaceAllString(pass, "")
	}

	length := len(pass)

	lowerCase := regexp.MustCompile(`[a-z]`)
	lowerMatch := lowerCase.FindStringSubmatch(pass)
	if len(lowerMatch) > 0 {
		countCase += 1
	}

	upperCase := regexp.MustCompile(`[A-Z]`)
	upperMatch := upperCase.FindStringSubmatch(pass)
	if len(upperMatch) > 0 {
		countCase += 1
	}

	numberCase := regexp.MustCompile(`[\d]`)
	numberMatch := numberCase.FindStringSubmatch(pass)
	if len(numberMatch) > 0 {
		countCase += 1
	}

	characterCase := regexp.MustCompile(`[^\w]`)
	characterMatch := characterCase.FindStringSubmatch(pass)
	if len(characterMatch) > 0 {
		countCase += 1
	}

	if length <= 6 {
		switch countCase {
		case 4:
			return "Medium"
		default:
			return "Weak"
		}

	} else if length > 6 && length <= 10 {
		switch countCase {
		case 4, 3:
			return "Strong"
		case 2:
			return "Medium"
		case 1, 0:
			return "Weak"

		}
	} else {
		if countCase < 2 {
			return "Medium"
		}
	}

	return "Strong"
}
