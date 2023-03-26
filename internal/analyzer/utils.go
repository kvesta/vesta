package analyzer

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"

	version2 "github.com/hashicorp/go-version"
	"github.com/kvesta/vesta/config"
)

var (
	baseMatch = regexp.MustCompile(`^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$`)

	passKey = []*regexp.Regexp{
		regexp.MustCompile(`(?i)pass`),
		regexp.MustCompile(`(?i)pwd`),
		regexp.MustCompile(`(?i)token`),
		regexp.MustCompile(`(?i)secret`),
		regexp.MustCompile(`(?i)key$`),
		regexp.MustCompile(`(?i)key[^.]`),
	}

	dangerPrefixMountPaths = []string{"/etc/crontab", "/private/etc",
		"/var/run", "/run/containerd", "/sys/fs/cgroup", "/root/.ssh"}

	dangerFullPaths = []string{"/", "/etc", "/proc", "/proc/1", "/sys", "/root", "/var/log"}

	namespaceWhileList = []string{"istio-system", "kube-system", "kube-public",
		"kubesphere-router-gateway", "kubesphere-system", "openshift-sdn", "openshift-node", "openshift-infra"}

	dangerCaps = []string{"SYS_ADMIN", "CAP_SYS_ADMIN", "CAP_SYS_PTRACE", "CAP_SYS_MODULE",
		"CAP_SYS_CHROOT", "SYS_PTRACE", "CAP_BPF", "DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "NET_ADMIN"}

	unsafeAnnotations = map[string]AnType{
		"sidecar.istio.io/proxyImage":                              {component: "istio", level: "warning"},
		"sidecar.istio.io/userVolumeMount":                         {component: "istio", level: "warning"},
		"seccomp.security.alpha.kubernetes.io/allowedProfileNames": {component: "PodSecurityPolicy", level: "medium", Values: []string{"*"}},
		"apparmor.security.beta.kubernetes.io/allowedProfileNames": {component: "PodSecurityPolicy", level: "medium", Values: []string{"*"}},
		"security.alpha.kubernetes.io/sysctls": {component: "k8s", level: "low",
			Values: []string{"kernel.shm_rmid_forced=0", "net.core.", "kernel.shm", "kernel.msg", "kernel.sem", "fs.mqueue."}},
	}
)

type AnType struct {
	component string
	level     string
	Values    []string
}

func checkWeakPassword(pass string) string {
	countCase := 0

	pass = string(decodeBase64(pass))

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

type MalReporter struct {
	Types MalLevel
	Score float64
	Plain string
}

type MalLevel int8

const (
	// Unknown item represents the content is normal.
	Unknown MalLevel = 0
	// Confusion item represents the content matches many safe rules.
	Confusion MalLevel = 1
	// Executable item represents the content is an executable binary.
	Executable MalLevel = 2
)

func maliciousContentCheck(command string) MalReporter {

	rep := MalReporter{}

	// Some string is encoded many times
	sDec := decodeBase64(command)

	switch {
	case bytes.HasPrefix(sDec, []byte("\x7fELF")), strings.HasPrefix(string(sDec), "\\x7F\\x45\\x4C\\x46"):
		rep.Types = Executable
		rep.Plain = "ELF LSB executable binary"
		rep.Score = 0.9

		return rep

	case bytes.HasPrefix(sDec, []byte("MZ")), strings.HasPrefix(string(sDec), "\\x4d\\x5a"):
		rep.Types = Executable
		rep.Plain = "PE32+ executable for MS Windows"
		rep.Score = 0.9

	default:
		// ignore
	}

	commandPlain := string(sDec)

	if isPath(commandPlain) {
		rep.Types = Unknown
		return rep
	}

	keySymbolReg := regexp.MustCompile(`[~$&<>*!():=.|/\\+#;]`)
	SymbolCount := len(keySymbolReg.FindAllString(commandPlain, -1))

	keyFuncs := []string{"syscall", "open", "select", "fork", "proc", "system", "exit",
		"/dev/tcp/", "/bin/sh", "/bin/bash", "subprocess.", "fsockopen", "TCPSocket", "()", "->"}
	var funcCount int
	for _, f := range keyFuncs {
		funcCount += strings.Count(commandPlain, f) * len(f)
	}

	replacer := strings.NewReplacer(" ", "", "\n", "", "\t", "")
	commandLen := len(replacer.Replace(commandPlain))

	score := float64(SymbolCount*3+funcCount) / float64(commandLen)
	ratio := math.Pow(10, float64(2))
	score = math.Round(score*ratio) / ratio

	if commandLen < 30 {
		score = 0.0
	}

	if score > 0.75 {
		rep.Types = Confusion
	} else {
		rep.Types = Unknown
	}

	rep.Score = score
	if len(commandPlain) > 50 {
		rep.Plain = commandPlain[:50]

		return rep
	}

	rep.Plain = commandPlain

	return rep
}

func decodeBase64(content string) []byte {
	normalRegx := regexp.MustCompile(`[\w]`)

	res := []byte(content)

	for i := 0; i < 10; i++ {

		if !baseMatch.Match(res) {
			break
		}

		de, err := base64.StdEncoding.DecodeString(string(res))

		if err != nil || len(de) < 1 {
			res = []byte(content)
			break
		}

		if len(normalRegx.FindAllSubmatch(de, -1)) < 1 {
			break
		}

		res = de
	}

	return res
}

func standardDeviation[T float64 | int](num []T) float64 {
	var sum, mean, sd float64
	length := len(num)
	for i := 1; i <= length; i++ {
		sum += float64(num[i-1])
	}
	mean = sum / float64(length)
	for j := 0; j < length; j++ {
		sd += math.Pow(float64(num[j])-mean, 2)
	}
	return sd / float64(length)
}

func isPath(content string) bool {
	pathRegex := regexp.MustCompile(`(/{0,1}(([\w.\-?]|(\\ ))+/)*([\w.\-?]|(\\ ))+)|/`)

	replacer := strings.NewReplacer(";", "", ":", "")
	pruneContent := replacer.Replace(content)
	pathMatch := pathRegex.FindStringSubmatch(pruneContent)
	if len(pathMatch) > 0 && pathMatch[0] == pruneContent {
		return true
	}

	return false
}
