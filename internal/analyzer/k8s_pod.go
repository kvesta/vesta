package analyzer

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/kvesta/vesta/config"
	v1 "k8s.io/api/core/v1"
)

func checkPodVolume(config v1.Volume) (bool, []*threat) {
	tlist := []*threat{}
	var vuln = false

	hostPath := config.HostPath
	if hostPath != nil {
		//volumePath := filepath.Dir(hostPath.Path)
		volumePath := hostPath.Path

		if isVuln := checkMountPath(volumePath); isVuln {
			th := &threat{
				Param: fmt.Sprintf("volumes name: %s", config.Name),
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

func checkPodPrivileged(config v1.Container) (bool, []*threat) {
	tlist := []*threat{}
	var vuln = false

	if config.SecurityContext != nil {

		// check capabilities of pod
		capList := ""
		if config.SecurityContext.Capabilities != nil {
			adds := config.SecurityContext.Capabilities.Add
			for _, ad := range adds {
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
						"capabilities", config.Name),
					Value:    capList,
					Type:     "capabilities.add",
					Describe: "There has a potential container escape in privileged module.",
					Severity: "critical",
				}
				tlist = append(tlist, th)
			}
		}

		if config.SecurityContext.Privileged != nil && *config.SecurityContext.Privileged {
			th := &threat{
				Param: fmt.Sprintf("sidecar name: %s | "+
					"Privileged", config.Name),
				Value:    "true",
				Type:     "Sidecar Privileged",
				Describe: "There has a potential container escape in privileged module.",
				Severity: "critical",
			}
			tlist = append(tlist, th)
			vuln = true
		}

		if config.SecurityContext.AllowPrivilegeEscalation != nil && *config.SecurityContext.AllowPrivilegeEscalation {
			th := &threat{
				Param: fmt.Sprintf("sidecar name: %s | "+
					"AllowPrivilegeEscalation", config.Name),
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

func (ks KScanner) checkSidecarEnv(config v1.Container, ns string) (bool, []*threat) {
	var vuln = false
	tlist := []*threat{}

	// Check Pod Env
	for _, env := range config.Env {

		needCheck := false

		if env.ValueFrom != nil {
			switch {
			case env.ValueFrom.SecretKeyRef != nil:
				secretRef := env.ValueFrom.SecretKeyRef
				if ok, th := ks.checkSecretFromName(ns, secretRef.Key, secretRef.Name, env.Name); ok {
					th.Param = fmt.Sprintf("sidecar name: %s | env", config.Name)

					tlist = append(tlist, th)
					vuln = true
				}

				continue

			case env.ValueFrom.ConfigMapKeyRef != nil:
				configRef := env.ValueFrom.ConfigMapKeyRef
				if ok, th := ks.checkConfigFromName(ns, configRef.Name, configRef.Key, env.Name); ok {
					th.Param = fmt.Sprintf("sidecar name: %s | env", config.Name)

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
					Param:    fmt.Sprintf("sidecar name: %s | env", config.Name),
					Value:    fmt.Sprintf("%s:%s", env.Name, env.Value),
					Type:     "Sidecar Env",
					Describe: fmt.Sprintf("Container '%s' has found weak password: '%s'.", config.Name, env.Value),
					Severity: "high",
				}

				tlist = append(tlist, th)
				vuln = true

			case "Medium":
				th := &threat{
					Param: fmt.Sprintf("sidecar name: %s | env", config.Name),
					Value: fmt.Sprintf("%s:%s", env.Name, env.Value),
					Type:  "Sidecar Env",
					Describe: fmt.Sprintf("Container '%s' has found password '%s' "+
						"need to be reinforeced.", config.Name, env.Value),
					Severity: "medium",
				}

				tlist = append(tlist, th)
				vuln = true
			}
		}

	}

	// Check pod envFrom
	for _, envFrom := range config.EnvFrom {
		switch {
		case envFrom.ConfigMapRef != nil:
			configRef := envFrom.ConfigMapRef
			configReg := regexp.MustCompile(`ConfigMap Name: (.*)? Namespace: (.*)`)
			if ok, th := ks.checkConfigVulnType(ns, configRef.Name, "ConfigMap", configReg); ok {
				th.Param = fmt.Sprintf("sidecar name: %s | env", config.Name)

				tlist = append(tlist, th)
				vuln = true
			}

		case envFrom.SecretRef != nil:
			configRef := envFrom.SecretRef
			configReg := regexp.MustCompile(`Secret Name: (.*)? Namespace: (.*)`)
			if ok, th := ks.checkConfigVulnType(ns, configRef.Name, "Secret", configReg); ok {
				th.Param = fmt.Sprintf("sidecar name: %s | env", config.Name)

				tlist = append(tlist, th)
				vuln = true
			}

		default:
			//ignore
		}
	}

	return vuln, tlist
}

func checkResourcesLimits(config v1.Container) (bool, []*threat) {
	var vuln = false
	tlist := []*threat{}

	if len(config.Resources.Limits) < 1 {
		th := &threat{
			Param: fmt.Sprintf("sidecar name: %s | "+
				"Resource", config.Name),
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

	if config.Resources.Limits.Memory().String() == "0" {
		th := &threat{
			Param: fmt.Sprintf("sidecar name: %s | "+
				"Resource", config.Name),
			Value:     "memory",
			Type:      "Sidecar Resource",
			Describe:  "Memory usage is not limited.",
			Reference: "https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/",
			Severity:  "low",
		}

		tlist = append(tlist, th)
		vuln = true
	}

	if config.Resources.Limits.Cpu().String() == "0" {
		th := &threat{
			Param: fmt.Sprintf("sidecar name: %s | "+
				"Resource", config.Name),
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
func checkPodAccountService(config v1.Container, rv RBACVuln) (bool, []*threat) {
	var vuln = false
	tlist := []*threat{}

	for _, vc := range config.VolumeMounts {
		if vc.MountPath == "/var/run/secrets/kubernetes.io/serviceaccount" {

			th := &threat{
				Param: fmt.Sprintf("sidecar name: %s | "+
					"automountServiceAccountToken", config.Name),
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
