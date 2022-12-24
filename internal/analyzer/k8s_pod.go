package analyzer

import (
	"fmt"
	"path/filepath"

	v1 "k8s.io/api/core/v1"
)

func checkPodVolume(config v1.Volume) (bool, []*threat) {
	tlist := []*threat{}
	var vuln = false

	hostPath := config.HostPath
	if hostPath != nil {
		volumePath := filepath.Dir(hostPath.Path)

		if isVuln := checkMountPath(volumePath); isVuln {
			th := &threat{
				Param: config.Name,
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
					Param:    "capabilities",
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
				Param:    "Privileged",
				Value:    "true",
				Type:     "Pod",
				Describe: "There has a potential container escape in privileged module.",
				Severity: "critical",
			}
			tlist = append(tlist, th)
			vuln = true
		}

		if config.SecurityContext.AllowPrivilegeEscalation != nil && *config.SecurityContext.AllowPrivilegeEscalation {
			th := &threat{
				Param:    "AllowPrivilegeEscalation",
				Value:    "true",
				Type:     "Pod",
				Describe: "There has a potential container escape in privileged module.",
				Severity: "critical",
			}
			tlist = append(tlist, th)
			vuln = true
		}

	}

	return vuln, tlist
}

func checkResourcesLimits(config v1.Container) (bool, []*threat) {
	var vuln = false
	tlist := []*threat{}

	if len(config.Resources.Limits) < 1 {
		th := &threat{
			Param:     "Resource",
			Value:     "memory, cpu,\nephemeral-storage",
			Type:      "Pod",
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
			Param:     "Resource",
			Value:     "memory",
			Type:      "Pod",
			Describe:  "Memory usage is not limited.",
			Reference: "https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/",
			Severity:  "low",
		}

		tlist = append(tlist, th)
		vuln = true
	}

	if config.Resources.Limits.Cpu().String() == "0" {
		th := &threat{
			Param:     "Resource",
			Value:     "cpu",
			Type:      "Pod",
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
func checkPodAccountService(config v1.Container) (bool, []*threat) {
	var vuln = false
	tlist := []*threat{}

	for _, vc := range config.VolumeMounts {
		if vc.MountPath == "/var/run/secrets/kubernetes.io/serviceaccount" {

			th := &threat{
				Param:    "automountServiceAccountToken",
				Value:    "true",
				Type:     vc.Name,
				Describe: "Mount service account has a potential sensitive data leakage.",
				Severity: "low",
			}
			tlist = append(tlist, th)
			vuln = true
		}
	}

	return vuln, tlist
}
