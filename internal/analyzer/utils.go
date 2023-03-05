package analyzer

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	version2 "github.com/hashicorp/go-version"
	"github.com/kvesta/vesta/config"
)

var (
	passKey = []*regexp.Regexp{
		regexp.MustCompile(`(?i)pass`),
		regexp.MustCompile(`(?i)pwd`),
		regexp.MustCompile(`(?i)token`),
		regexp.MustCompile(`(?i)secret`),
		regexp.MustCompile(`(?i)key`),
	}

	dangerPrefixMountPaths = []string{"/etc/crontab", "/private/etc",
		"/var/run", "/run/containerd", "/sys/fs/cgroup", "/root/.ssh"}

	dangerFullPaths = []string{"/", "/etc", "/proc", "/proc/1", "/sys", "/root", "/var/log"}

	namespaceWhileList = []string{"istio-system", "kube-system", "kube-public",
		"kubesphere-router-gateway", "kubesphere-system", "openshift-sdn", "openshift-node"}

	dangerCaps = []string{"SYS_ADMIN", "CAP_SYS_ADMIN", "CAP_SYS_PTRACE", "CAP_SYS_MODULE",
		"CAP_SYS_CHROOT", "SYS_PTRACE", "CAP_BPF", "DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "NET_ADMIN"}

	unsafeAnnotations = map[string]AnType{
		"sidecar.istio.io/proxyImage":          {component: "istio", level: "warning"},
		"sidecar.istio.io/userVolumeMount":     {component: "istio", level: "warning"},
		"security.alpha.kubernetes.io/sysctls": {component: "k8s", level: "low"},
	}
)

type AnType struct {
	component string
	level     string
}

func checkWeakPassword(pass string) string {
	countCase := 0

	// Particularly checking the keyword
	keyWords := []string{"password", "admin", "qwerty", "1q2w3e", "123456"}
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
		countCase += 2
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
		case 3, 4:
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
	path = strings.TrimSuffix(path, "/")
	return checkPrefixMountPaths(path) || checkFullPaths(path)
}

func sortSeverity(threats []*threat) {
	sort.SliceStable(threats, func(i, j int) bool {
		return config.SeverityMap[threats[i].Severity] > config.SeverityMap[threats[j].Severity]
	})
}
