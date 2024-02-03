package analyzer

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"

	version2 "github.com/hashicorp/go-version"
	"github.com/kvesta/vesta/config"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

	// Reference: https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv
	cveRuncRegex = regexp.MustCompile(`(?i)/proc/self/fd`)

	dangerPrefixMountPaths = []string{"/etc/crontab", "/var/run", "/run/containerd",
		"/sys/fs/cgroup", "/root/.ssh"}

	dangerFullPaths = []string{"/", "/etc", "/proc", "/proc/1", "/sys", "/root", "/var/log",
		"/c", "/c/Users", "/private/etc"}

	namespaceWhileList = []string{"istio-system", "kube-system", "kube-public", "ingress-nginx",
		"kubesphere-router-gateway", "kubesphere-system", "openshift-sdn", "openshift-node", "openshift-infra"}

	dangerCaps = []string{"SYS_ADMIN", "CAP_SYS_ADMIN", "CAP_SYS_PTRACE", "CAP_SYS_MODULE",
		"CAP_SYS_CHROOT", "SYS_PTRACE", "CAP_BPF", "DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "NET_ADMIN"}

	unsafeAnnotations = map[string]AnType{
		"sidecar.istio.io/proxyImage":                              {component: "istio", level: "warning"},
		"sidecar.istio.io/userVolumeMount":                         {component: "istio", level: "warning"},
		"seccomp.security.alpha.kubernetes.io/allowedProfileNames": {component: "PodSecurityPolicy", level: "medium", Values: []string{"*"}},
		"apparmor.security.beta.kubernetes.io/allowedProfileNames": {component: "PodSecurityPolicy", level: "medium", Values: []string{"*"}},
		"nginx.ingress.kubernetes.io/permanent-redirect":           {component: "nginx ingress", level: "medium", Values: []string{"{", ";", "$", "(", "'", `""`}},
		"nginx.ingress.kubernetes.io/server-snippet":               {component: "nginx ingress", level: "medium", Values: []string{"serviceaccount/token"}},
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
		maxv, err := version2.NewVersion(maxVersion[1:])
		if err != nil {
			return false
		}

		if strings.Contains(minVersion, "=") {
			minv, err := version2.NewVersion(minVersion[1:])
			if err != nil {
				return false
			}

			if k1.Compare(maxv) <= 0 && k1.Compare(minv) >= 0 {
				return true
			}
		} else {
			minv, err := version2.NewVersion(minVersion)
			if err != nil {
				return false
			}

			if k1.Compare(maxv) <= 0 && k1.Compare(minv) > 0 {
				return true
			}
		}

	} else {
		maxv, err := version2.NewVersion(maxVersion)
		if err != nil {
			return false
		}

		if strings.Contains(minVersion, "=") {
			minv, err := version2.NewVersion(minVersion[1:])
			if err != nil {
				return false
			}

			if k1.Compare(maxv) < 0 && k1.Compare(minv) >= 0 {

				return true
			}
		} else {
			minv, err := version2.NewVersion(minVersion)
			if err != nil {
				return false
			}

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

	keySymbolReg := regexp.MustCompile(`[~$&<>*!():=.|\\+#;]`)
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

func (ks *KScanner) findEnvValue(container v1.Container, name, ns string) string {
	var value string

	for _, env := range container.Env {
		if env.Name == name {
			if env.ValueFrom != nil {
				switch {
				case env.ValueFrom.ConfigMapKeyRef != nil:
					configRef := env.ValueFrom.ConfigMapKeyRef
					value = ks.findSecretOrConfigMapValue(configRef.Name, "ConfigMap", ns)

				case env.ValueFrom.SecretKeyRef != nil:
					configRef := env.ValueFrom.SecretKeyRef
					value = ks.findSecretOrConfigMapValue(configRef.Name, "Secret", ns)

				default:
					//ignore
				}
			} else {
				value = env.Value
			}

			break
		}
	}

	return value
}

func (ks *KScanner) getRBACVulnType(ns string) RBACVuln {
	rbv := RBACVuln{
		Severity: "warning",
	}
	clusterNames := []string{}
	roleNames := []string{}

	getInfo := func(param string) (string, string) {
		paramSplit := strings.Split(param, "|")
		bindingName := strings.Split(paramSplit[0], ":")[1]
		bindingName = strings.TrimSpace(bindingName)
		nameSpace := strings.Split(paramSplit[len(paramSplit)-2], ":")[1]
		nameSpace = strings.TrimSpace(nameSpace)
		return bindingName, nameSpace
	}

	for _, t := range ks.VulnConfigures {

		switch t.Type {
		case "ClusterRoleBinding", "RoleBinding":
			bn, n := getInfo(t.Param)
			switch {
			case n != ns && n != "all", t.Severity == "warning":
				continue
			case config.SeverityMap[rbv.Severity] <
				config.SeverityMap[t.Severity]:
				rbv.Severity = t.Severity
			}

			if t.Type == "ClusterRoleBinding" {
				clusterNames = append(clusterNames, bn)
			} else {
				roleNames = append(roleNames, bn)
			}

		default:
			// ignore
		}
	}

	rbv.RoleBinding = strings.Join(roleNames, ", ")
	rbv.ClusterRoleBinding = strings.Join(clusterNames, ", ")

	return rbv
}

func (ks *KScanner) checkConfigVulnType(ns, name, ty string, configReg *regexp.Regexp) (bool, *threat) {
	var vuln = false
	th := &threat{}

	for _, t := range ks.VulnConfigures {

		if t.Type != ty {
			continue
		}

		configMatch := configReg.FindStringSubmatch(t.Param)
		configName := strings.TrimSpace(configMatch[1])
		namespace := strings.TrimSpace(configMatch[2])
		if configName == name && namespace == ns {
			th = t
			th.Type = "Sidecar EnvFrom"
			th.Describe = "Sidecar envFrom " + th.Describe

			vuln = true
			break
		}
	}

	return vuln, th
}

func (ks *KScanner) getPodFromLabels(ns string, matchLabels map[string]string) v1.Pod {
	p := v1.Pod{}

	for k, v := range matchLabels {
		targetPod, err := ks.KClient.
			CoreV1().
			Pods(ns).
			List(context.TODO(),
				metav1.ListOptions{
					LabelSelector: fmt.Sprintf("%s=%s", k, v),
				})

		if err != nil {
			continue
		}

		if len(targetPod.Items) > 0 {
			p = targetPod.Items[0]
			break
		}
	}

	return p
}

// addExtraPod which in the white list namespace
func (ks *KScanner) addExtraPod(ns string, p v1.Pod, vList []*threat) {
	isChecked := false
	for _, vulnPod := range ks.VulnContainers {
		if vulnPod.ContainerName == p.Name &&
			vulnPod.Namepsace == ns {
			isChecked = true

			break
		}
	}

	if !isChecked && p.Name != "" {
		sortSeverity(vList)

		c := &container{
			ContainerName: p.Name,
			Namepsace:     ns,
			Status:        string(p.Status.Phase),
			NodeName:      p.Spec.NodeName,
			Threats:       vList,
		}

		ks.VulnContainers = append(ks.VulnContainers, c)
	}
}

// prunePod assesses whether a pod need to check if namespace of pod in white list
func (ks *KScanner) prunePod(ns, podName string) (bool, error) {
	pods, err := ks.KClient.
		CoreV1().
		Pods(ns).
		List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return false, err
	}

	type PodStatus struct {
		Age      float64
		Restarts int
	}

	p := PodStatus{}

	podNumber := len(pods.Items)

	ageWeight := make([]float64, podNumber-1)
	restartWeight := make([]int, podNumber-1)

	index := 0
	for _, pod := range pods.Items {
		age := time.Since(pod.CreationTimestamp.Time)
		restarts := pod.Status.ContainerStatuses[0].RestartCount

		if pod.Name == podName {
			p.Age = math.Round(age.Hours())
			p.Restarts = int(restarts)
			continue
		}

		ageWeight[index] = math.Round(age.Hours())
		restartWeight[index] = int(restarts)
		index += 1
	}

	sort.Float64s(ageWeight)
	sort.Ints(restartWeight)
	ageDeviation := standardDeviation[float64](ageWeight)
	restartDeviation := math.Sqrt(standardDeviation[int](restartWeight))

	ageCount := map[float64]int{}
	restartCount := map[int]int{}
	for i := 0; i < podNumber-1; i++ {
		age := ageWeight[i]
		restarts := restartWeight[i]

		if _, ok := ageCount[age]; ok {
			ageCount[age] += 1
		} else {
			ageCount[age] = 1
		}

		if _, ok := restartCount[restarts]; ok {
			restartCount[restarts] += 1
		} else {
			restartCount[restarts] = 1
		}
	}

	score := 0.0

	for number, count := range ageCount {
		if math.Abs(p.Age-number) > ageDeviation {
			score = math.Max(score, float64(count)/float64(podNumber-1))
		}
	}

	// compare to the oldest operation
	score += 0.2 * math.Abs(float64(p.Age)-ageWeight[podNumber-2]) / (ageWeight[podNumber-2] / 960)

	rscore := 0.0
	for number, count := range restartCount {
		if math.Abs(float64(p.Restarts-number)) > restartDeviation {
			rscore = math.Max(rscore, float64(count)/float64(podNumber-1))
		}
	}

	score += rscore

	if score < 0.7 {
		return true, nil
	}

	return false, nil
}
