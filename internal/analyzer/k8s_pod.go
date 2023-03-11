package analyzer

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/kvesta/vesta/config"
	v1 "k8s.io/api/core/v1"
)

func (ks KScanner) podAnalyze(podSpec v1.PodSpec, rv RBACVuln, ns, podName string) []*threat {
	vList := []*threat{}

	for _, v := range podSpec.Volumes {
		if ok, tlist := checkPodVolume(v); ok {
			vList = append(vList, tlist...)
		}
	}

	for _, sp := range podSpec.Containers {

		// Skip some sidecars
		if sp.Name == "istio-proxy" {
			// Try to check the istio header `X-Envoy-Peer-Metadata`
			// reference: https://github.com/istio/istio/issues/17635
			if ok, tlist := ks.checkIstioHeader(podName, ns, podSpec.Containers[0].Name); ok {
				vList = append(vList, tlist...)
			}

			continue
		}

		if ok, tlist := checkPodPrivileged(sp); ok {
			vList = append(vList, tlist...)
		}

		if ok, tlist := checkPodAccountService(sp, rv); ok {
			vList = append(vList, tlist...)
		}

		if ok, tlist := checkResourcesLimits(sp); ok {
			vList = append(vList, tlist...)
		}

		if ok, tlist := ks.checkSidecarEnv(sp, ns); ok {
			vList = append(vList, tlist...)
		}

		if ok, tlist := ks.checkPodCommand(sp, ns); ok {
			vList = append(vList, tlist...)
		}

	}

	return vList
}

func checkPodVolume(container v1.Volume) (bool, []*threat) {
	tlist := []*threat{}
	var vuln = false

	hostPath := container.HostPath
	if hostPath != nil {
		//volumePath := filepath.Dir(hostPath.Path)
		volumePath := hostPath.Path

		if isVuln := checkMountPath(volumePath); isVuln {
			th := &threat{
				Param: fmt.Sprintf("volumes name: %s", container.Name),
				Value: volumePath,
				Type:  string(*hostPath.Type),
				Describe: fmt.Sprintf("Mounting '%s' is suffer vulnerable of "+
					"container escape.", volumePath),
				Severity: "critical",
			}

			tlist = append(tlist, th)
			vuln = true
		}
	}

	return vuln, tlist
}

func checkPodPrivileged(container v1.Container) (bool, []*threat) {
	tlist := []*threat{}
	var vuln = false

	if container.SecurityContext != nil {

		// check capabilities of pod
		// Ignore the checking of cap_drop refer to:
		// https://stackoverflow.com/questions/63162665/docker-compose-order-of-cap-drop-and-cap-add
		capList := ""
		if container.SecurityContext.Capabilities != nil {

			adds := container.SecurityContext.Capabilities.Add
			for _, ad := range adds {
				if ad == "ALL" {
					capList = "ALL"
					vuln = true
					break
				}

				for _, c := range dangerCaps {
					if string(ad) == c {
						capList += c + " "
						vuln = true
					}
				}
			}

			if vuln {
				th := &threat{
					Param: fmt.Sprintf("sidecar name: %s | "+
						"capabilities", container.Name),
					Value:    capList,
					Type:     "capabilities.add",
					Describe: "There has a potential container escape in privileged module.",
					Severity: "critical",
				}
				tlist = append(tlist, th)
			}
		}

		if container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
			th := &threat{
				Param: fmt.Sprintf("sidecar name: %s | "+
					"Privileged", container.Name),
				Value:    "true",
				Type:     "Sidecar Privileged",
				Describe: "There has a potential container escape in privileged module.",
				Severity: "critical",
			}
			tlist = append(tlist, th)
			vuln = true
		}

		if container.SecurityContext.AllowPrivilegeEscalation != nil && *container.SecurityContext.AllowPrivilegeEscalation {
			th := &threat{
				Param: fmt.Sprintf("sidecar name: %s | "+
					"AllowPrivilegeEscalation", container.Name),
				Value:    "true",
				Type:     "Sidecar Privileged",
				Describe: "There has a potential container escape in privileged module.",
				Severity: "critical",
			}
			tlist = append(tlist, th)
			vuln = true
		}

	}

	return vuln, tlist
}

func (ks KScanner) checkSidecarEnv(container v1.Container, ns string) (bool, []*threat) {
	var vuln = false
	tlist := []*threat{}

	// Check Pod Env
	for _, env := range container.Env {

		needCheck := false

		if env.ValueFrom != nil {
			switch {
			case env.ValueFrom.SecretKeyRef != nil:
				secretRef := env.ValueFrom.SecretKeyRef
				if ok, th := ks.checkSecretFromName(ns, secretRef.Key, secretRef.Name, env.Name); ok {
					th.Param = fmt.Sprintf("sidecar name: %s | env", container.Name)

					tlist = append(tlist, th)
					vuln = true
				}

				continue

			case env.ValueFrom.ConfigMapKeyRef != nil:
				configRef := env.ValueFrom.ConfigMapKeyRef
				if ok, th := ks.checkConfigFromName(ns, configRef.Name, configRef.Key, env.Name); ok {
					th.Param = fmt.Sprintf("sidecar name: %s | env", container.Name)

					tlist = append(tlist, th)
					vuln = true
				}

				continue
			}
		}

		for _, p := range passKey {
			if p.MatchString(env.Name) && env.ValueFrom == nil {
				needCheck = true
				break
			}
		}

		if needCheck {
			switch checkWeakPassword(env.Value) {
			case "Weak":
				th := &threat{
					Param:    fmt.Sprintf("sidecar name: %s | env", container.Name),
					Value:    fmt.Sprintf("%s: %s", env.Name, env.Value),
					Type:     "Sidecar Env",
					Describe: fmt.Sprintf("Container '%s' has found weak password: '%s'.", container.Name, env.Value),
					Severity: "high",
				}

				tlist = append(tlist, th)
				vuln = true

			case "Medium":
				th := &threat{
					Param: fmt.Sprintf("sidecar name: %s | env", container.Name),
					Value: fmt.Sprintf("%s: %s", env.Name, env.Value),
					Type:  "Sidecar Env",
					Describe: fmt.Sprintf("Container '%s' has found password '%s' "+
						"need to be reinforeced.", container.Name, env.Value),
					Severity: "medium",
				}

				tlist = append(tlist, th)
				vuln = true
			}
		}

		detect := maliciousContentCheck(env.Value)
		th := &threat{
			Param: fmt.Sprintf("sidecar name: %s | env", container.Name),
			Value: fmt.Sprintf("%s: %s", env.Name, detect.Plain),
			Type:  "Sidecar Env",
		}
		switch detect.Types {
		case Confusion:
			th.Describe = fmt.Sprintf("Container '%s' finds high risk content(score: %.2f out of 1.0), "+
				"which is a suspect command backdoor. ", container.Name, detect.Score)
			th.Severity = "high"

			tlist = append(tlist, th)
			vuln = true
		case Executable:
			th.Describe = fmt.Sprintf("An executable format of content is detected in Container '%s', "+
				"which is a potential backdoor and scanning the vulnerability is highly recommended.", container.Name)
			th.Severity = "critical"

			tlist = append(tlist, th)
			vuln = true
		default:
			// ignore

		}

	}

	// Check pod envFrom
	for _, envFrom := range container.EnvFrom {
		switch {
		case envFrom.ConfigMapRef != nil:
			configRef := envFrom.ConfigMapRef
			configReg := regexp.MustCompile(`ConfigMap Name: (.*)? Namespace: (.*)`)
			if ok, th := ks.checkConfigVulnType(ns, configRef.Name, "ConfigMap", configReg); ok {
				th.Param = fmt.Sprintf("sidecar name: %s | env", container.Name)

				tlist = append(tlist, th)
				vuln = true
			}

		case envFrom.SecretRef != nil:
			configRef := envFrom.SecretRef
			configReg := regexp.MustCompile(`Secret Name: (.*)? Namespace: (.*)`)
			if ok, th := ks.checkConfigVulnType(ns, configRef.Name, "Secret", configReg); ok {
				th.Param = fmt.Sprintf("sidecar name: %s | env", container.Name)

				tlist = append(tlist, th)
				vuln = true
			}

		default:
			//ignore
		}
	}

	return vuln, tlist
}

func checkResourcesLimits(container v1.Container) (bool, []*threat) {
	var vuln = false
	tlist := []*threat{}

	if len(container.Resources.Limits) < 1 {
		th := &threat{
			Param: fmt.Sprintf("sidecar name: %s | "+
				"Resource", container.Name),
			Value:     "memory, cpu, ephemeral-storage",
			Type:      "Sidecar Resource",
			Describe:  "None of resources is be limited.",
			Reference: "https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/",
			Severity:  "low",
		}

		tlist = append(tlist, th)
		vuln = true

		return vuln, tlist
	}

	if container.Resources.Limits.Memory().String() == "0" {
		th := &threat{
			Param: fmt.Sprintf("sidecar name: %s | "+
				"Resource", container.Name),
			Value:     "memory",
			Type:      "Sidecar Resource",
			Describe:  "Memory usage is not limited.",
			Reference: "https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/",
			Severity:  "low",
		}

		tlist = append(tlist, th)
		vuln = true
	}

	if container.Resources.Limits.Cpu().String() == "0" {
		th := &threat{
			Param: fmt.Sprintf("sidecar name: %s | "+
				"Resource", container.Name),
			Value:     "cpu",
			Type:      "Sidecar Resource",
			Describe:  "CPU usage is not limited.",
			Reference: "https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/",
			Severity:  "low",
		}

		tlist = append(tlist, th)
		vuln = true
	}

	return vuln, tlist
}

// checkPodAccountService check the default mount of service account
func checkPodAccountService(container v1.Container, rv RBACVuln) (bool, []*threat) {
	var vuln = false
	tlist := []*threat{}

	for _, vc := range container.VolumeMounts {
		if vc.MountPath == "/var/run/secrets/kubernetes.io/serviceaccount" {

			th := &threat{
				Param: fmt.Sprintf("sidecar name: %s | "+
					"automountServiceAccountToken", container.Name),
				Value:    "true",
				Type:     vc.Name,
				Describe: "Mount service account has a potential sensitive data leakage.",
				Severity: "low",
			}

			switch rv.Severity {
			case "high":
				th.Severity = "critical"
				th.Describe = fmt.Sprintf("Mount service account and key permission are given, "+
					"which will cause a potential container escape. "+
					"Reference clsuterRolebind: %s | roleBinding: %s",
					rv.ClusterRoleBinding, rv.RoleBinding)
			case "medium":
				th.Severity = "high"
				th.Describe = fmt.Sprintf("Mount service account and view permission are given, "+
					"which will cause a sensitive data leakage. "+
					"Reference clsuterRolebind: %s | roleBinding: %s",
					rv.ClusterRoleBinding, rv.RoleBinding)

			case "low":
				th.Severity = "medium"
				th.Describe = fmt.Sprintf("Mount service account and some permission are given, "+
					"which will cause a potential data leakage. "+
					"Reference clsuterRolebind: %s | roleBinding: %s",
					rv.ClusterRoleBinding, rv.RoleBinding)
			default:
				//ignore
			}

			tlist = append(tlist, th)
			vuln = true
		}
	}

	return vuln, tlist
}

func checkPodAnnotation(ans map[string]string) (bool, []*threat) {
	var vuln = false
	tlist := []*threat{}

	for k, v := range ans {
		for n, t := range unsafeAnnotations {
			if k == n {

				th := &threat{
					Param: fmt.Sprintf("pod annotation"),
					Value: fmt.Sprintf("%s: %s", k, v),
					Type:  "Pod Annotation",
					Describe: fmt.Sprintf("Pod Annotation has some unsafe configs from %s"+
						" and value is `%s`.", t.component, v),
					Severity: t.level,
				}

				tlist = append(tlist, th)
				vuln = true
			}
		}
	}

	return vuln, tlist
}

func (ks KScanner) checkPodCommand(container v1.Container, ns string) (bool, []*threat) {
	var vuln = false
	tlist := []*threat{}

	comRex := regexp.MustCompile(`\$(\w+)`)

	commands := strings.Join(container.Command, " ") + " "
	commands += strings.Join(container.Args, " ")

	comMatch := comRex.FindAllStringSubmatch(commands, -1)
	if len(comMatch) > 1 {
		for _, v := range comMatch[1:] {
			val := ks.findEnvValue(container, v[1], ns)

			detect := maliciousContentCheck(val)
			switch detect.Types {
			case Confusion:
				th := &threat{
					Param: "Pod command",
					Value: fmt.Sprintf("command: %s", detect.Plain),
					Type:  "Pod Command",
					Describe: fmt.Sprintf("Container command has found high risk environment in '%s'(score: %.2f out of 1.0), "+
						"considering it as a backdoor.", v[0], detect.Score),
					Severity: "high",
				}

				tlist = append(tlist, th)
				vuln = true

				return vuln, tlist
			case Executable:
				th := &threat{
					Param: "Pod command",
					Value: fmt.Sprintf("command: %s", detect.Plain),
					Type:  "Pod Command",
					Describe: fmt.Sprintf("Container command has found executable risk environment in '%s', "+
						"considering it as a backdoor.", v[0]),
					Severity: "critical",
				}

				tlist = append(tlist, th)
				vuln = true

				return vuln, tlist
			default:
				// ignore
			}
		}
	}

	detect := maliciousContentCheck(commands)
	switch detect.Types {
	case Confusion:
		th := &threat{
			Param: "Pod command",
			Value: fmt.Sprintf("command: %s", detect.Plain),
			Type:  "Pod Command",
			Describe: fmt.Sprintf("Pod Command finds high risk content(score: %.2f out of 1.0), "+
				"considering it as a backdoor.", detect.Score),
			Severity: "high",
		}

		tlist = append(tlist, th)
		vuln = true

	case Executable:
		th := &threat{
			Param: "Pod command",
			Value: fmt.Sprintf("command: %s", detect.Plain),
			Type:  "Pod Command",
			Describe: "Container command is detected as a binary, " +
				"considering it as a backdoor.",
			Severity: "critical",
		}

		tlist = append(tlist, th)
		vuln = true

	default:
		// ignore
	}

	return vuln, tlist
}

func (ks KScanner) findEnvValue(container v1.Container, name, ns string) string {
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

func (ks KScanner) getRBACVulnType(ns string) RBACVuln {
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

func (ks KScanner) checkConfigVulnType(ns, name, ty string, configReg *regexp.Regexp) (bool, *threat) {
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
