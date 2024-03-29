package analyzer

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"

	"github.com/docker/docker/client"
	version2 "github.com/hashicorp/go-version"
	"github.com/kvesta/vesta/config"
	"github.com/kvesta/vesta/pkg/inspector"
	"github.com/kvesta/vesta/pkg/osrelease"
	"github.com/kvesta/vesta/pkg/vulnlib"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"
	certutil "k8s.io/client-go/util/cert"
)

func (ks *KScanner) getNodeInfor(ctx context.Context) error {
	nodes, err := ks.KClient.
		CoreV1().
		Nodes().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	ks.MasterNodes = make(map[string]*nodeInfo)

	for _, node := range nodes.Items {

		rolesInfo := &nodeInfo{
			IsMaster:   false,
			InternalIP: node.Status.Addresses[0].Address,
		}
		for role, _ := range node.Labels {
			if strings.HasPrefix(role, "node-role.kubernetes") {
				roleName := strings.Split(role, "/")[1]
				if roleName == "master" {
					rolesInfo.IsMaster = true
				}
			}
		}

		rolesInfo.Role = node.Labels
		ks.MasterNodes[node.Name] = rolesInfo

	}

	return nil
}

func (ks *KScanner) dockershimCheck(ctx context.Context) error {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}

	c := inspector.DockerApi{
		DCli: cli,
	}

	vulnCli := vulnlib.Client{}
	err = vulnCli.Init()
	if err != nil {
		return err
	}

	serverVersion, _ := c.GetDockerServerVersion(ctx)
	c.DCli.Close()

	// Checking kernel version
	kernelVersion, err := osrelease.GetKernelVersion(context.Background())
	if err != nil {
		log.Printf("failed to get kernel version: %v", err)
	}

	if ok, tlist := checkKernelVersion(vulnCli, kernelVersion); ok {
		ks.VulnConfigures = append(ks.VulnConfigures, tlist...)
	}

	// Check Docker server version
	if ok, tlist := checkDockerVersion(vulnCli, serverVersion); ok {
		ks.VulnConfigures = append(ks.VulnConfigures, tlist...)
	}

	// Check Kubernetes version
	if ok, tlist := checkK8sVersion(vulnCli, ks.Version); ok {
		ks.VulnConfigures = append(ks.VulnConfigures, tlist...)
	}

	return nil
}

// kernelCheck get /proc/version directly for non-Docker-Desktop
func (ks *KScanner) kernelCheck(ctx context.Context) error {

	cmd := exec.Command("cat", "/proc/version")

	stdout, err := cmd.Output()
	if err != nil {
		return err
	}

	vulnCli := vulnlib.Client{}
	err = vulnCli.Init()
	if err != nil {
		return err
	}

	kernelVersion := osrelease.KernelParse(string(stdout))

	if ok, tlist := checkKernelVersion(vulnCli, kernelVersion); ok {
		for _, th := range tlist {
			th.Type = "K8s kernel version"
		}
		ks.VulnConfigures = append(ks.VulnConfigures, tlist...)
	}

	if ok, tlist := checkK8sVersion(vulnCli, ks.Version); ok {
		ks.VulnConfigures = append(ks.VulnConfigures, tlist...)
	}

	return nil
}

func (ks *KScanner) checkPersistentVolume() error {
	log.Printf(config.Yellow("Begin PV and PVC analyzing"))

	tlist := []*threat{}
	pvs, err := ks.KClient.
		CoreV1().
		PersistentVolumes().
		List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		log.Printf("list persistentvolumes failed: %v", err)
		return err
	}
	for _, pv := range pvs.Items {

		// Check whether using the host mount
		if pv.Spec.HostPath == nil {
			continue
		}

		//pvPath := filepath.Dir(pv.Spec.HostPath.Path)
		pvPath := pv.Spec.HostPath.Path

		if isVuln := checkMountPath(pvPath); isVuln {
			th := &threat{
				Param: pv.Name,
				Value: pvPath,
				Type:  "PersistentVolume",
				Describe: fmt.Sprintf("Mount path '%s' is suffer vulnerable of "+
					"container escape and it is in using", pvPath),
				Severity: "critical",
			}

			// Check whether it is in using
			if pv.Status.Phase != "Bound" {
				th.Severity = "medium"
				th.Describe = fmt.Sprintf("Mount path '%s' is suffer vulnerable of "+
					"container escape but the status is '%s'", pvPath, pv.Status.Phase)
			}

			tlist = append(tlist, th)
		}

	}
	ks.VulnConfigures = append(ks.VulnConfigures, tlist...)
	return nil
}

type RBACVuln struct {
	Severity           string
	ClusterRoleBinding string
	RoleBinding        string
}

// checkPod check pod privileged and configure of server account
func (ks *KScanner) checkPod(ns string) error {
	if ns == "kubernetes-dashboard" {
		return ks.checkKuberDashboard()
	}

	pods, err := ks.KClient.
		CoreV1().
		Pods(ns).
		List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	rv := ks.getRBACVulnType(ns)

	for _, pod := range pods.Items {

		vList := ks.podAnalyze(pod.Spec, rv, ns, pod.Name)

		// Check pod annotations
		if ok, tlist := checkPodAnnotation(pod.Annotations); ok {
			vList = append(vList, tlist...)
		}

		if len(vList) > 0 {
			sortSeverity(vList)
			con := &container{
				ContainerName: pod.Name,
				Namepsace:     ns,
				Status:        string(pod.Status.Phase),
				NodeName:      pod.Spec.NodeName,
				Threats:       vList,
			}
			ks.VulnContainers = append(ks.VulnContainers, con)
		}

	}

	return nil
}

func (ks *KScanner) checkPodSecurityPolicy() error {
	log.Printf(config.Yellow("Begin PodSecurityPolicy analyzing"))

	psps, err := ks.KClient.
		PolicyV1beta1().
		PodSecurityPolicies().
		List(context.TODO(), metav1.ListOptions{})

	if err != nil {
		return err
	}

	for _, psp := range psps.Items {

		if psp.Spec.Privileged {
			th := &threat{
				Param: fmt.Sprintf("Policy Name: %s", psp.Name),
				Value: "Privileged",
				Type:  "PodSecurityPolicy",
				Describe: "PodSecurityPolicy tolerates the privileged module, " +
					"which can make the pod has a potential container escape.",
				Severity: "high",
			}

			ks.VulnConfigures = append(ks.VulnConfigures, th)
		}

		capList := ""
		for _, dcap := range psp.Spec.DefaultAddCapabilities {
			if dcap == "ALL" {
				capList = "ALL"
				break
			}

			for c, _ := range dangerCaps {
				if string(dcap) == c {
					capList += c + " "
				}
			}
		}

		if len(capList) > 0 {
			th := &threat{
				Param: fmt.Sprintf("Policy Name: %s", psp.Name),
				Value: fmt.Sprintf("defaultAddCapabilities: %s", capList),
				Type:  "PodSecurityPolicy",
				Describe: "PodSecurityPolicy tolerates the dangerous capabilities, " +
					"which can make the pod has a potential container escape.",
				Severity: "high",
			}

			ks.VulnConfigures = append(ks.VulnConfigures, th)
		}

		if psp.Spec.HostPID {
			th := &threat{
				Param: fmt.Sprintf("Policy Name: %s", psp.Name),
				Value: "HostPID",
				Type:  "PodSecurityPolicy",
				Describe: "PodSecurityPolicy is set the `hostPID`, " +
					"which attackers can see all the processes in physical machine.",
				Severity: "medium",
			}

			ks.VulnConfigures = append(ks.VulnConfigures, th)
		}

		if psp.Spec.HostNetwork {
			th := &threat{
				Param: fmt.Sprintf("Policy Name: %s", psp.Name),
				Value: "HostNetwork",
				Type:  "PodSecurityPolicy",
				Describe: "PodSecurityPolicy is set `HostNetwork`, " +
					"which will exposed the network of physical machine.",
				Severity: "medium",
			}

			ks.VulnConfigures = append(ks.VulnConfigures, th)
		}

		if psp.Spec.RunAsUser.Rule == "RunAsAny" {
			th := &threat{
				Param:    fmt.Sprintf("Policy Name: %s", psp.Name),
				Value:    "RunAsUser",
				Type:     "PodSecurityPolicy",
				Describe: "Pod shouldn't be run as arbitrary user.",
				Severity: "low",
			}

			ks.VulnConfigures = append(ks.VulnConfigures, th)
		}

	}

	return nil
}

func (ks *KScanner) checkDaemonSet(ns string) error {
	das, err := ks.KClient.
		AppsV1().
		DaemonSets(ns).
		List(context.TODO(), metav1.ListOptions{})

	if err != nil {
		return err
	}

	rv := ks.getRBACVulnType(ns)

	for _, da := range das.Items {

		p := ks.getPodFromLabels(da.Namespace, da.Spec.Selector.MatchLabels)

		vList := ks.podAnalyze(da.Spec.Template.Spec, rv, ns, p.Name)

		if len(vList) > 0 {

			severity := "low"
			for _, v := range vList {
				if config.SeverityMap[severity] < config.SeverityMap[v.Severity] {
					severity = v.Severity
				}
			}

			// Skip the low risk
			if severity == "low" {
				return nil
			}

			var containerImages string

			for _, im := range da.Spec.Template.Spec.Containers {
				imageSplit := strings.Split(im.Image, "/")
				containerImages += strings.Join(imageSplit, "/ ") + " | "
			}

			th := &threat{
				Param:    fmt.Sprintf("name: %s | namespace: %s", da.Name, da.Namespace),
				Value:    fmt.Sprintf("images: %s", containerImages),
				Type:     "DaemonSet",
				Describe: fmt.Sprintf("Daemonset has set the unsafe pod \"%s\".", p.Name),
				Severity: severity,
			}

			ks.VulnConfigures = append(ks.VulnConfigures, th)

			// Check the results whether the daemonset pod has been checked
			ks.addExtraPod(da.Namespace, p, vList)
		}

	}

	return nil
}

// checkJobsOrCornJob check job and cronjob whether have malicious command
func (ks *KScanner) checkJobsOrCornJob(ns string) error {
	jobs, err := ks.KClient.
		BatchV1().
		Jobs(ns).
		List(context.TODO(), metav1.ListOptions{})

	rv := ks.getRBACVulnType(ns)

	if err != nil {
		if strings.Contains(err.Error(), "could not find the requested resource") {
			goto cronJob
		}

		return err
	}

	for _, job := range jobs.Items {
		for _, con := range job.Spec.Template.Spec.Containers {
			command := strings.Join(con.Command, " ")
			detect := maliciousContentCheck(command)
			switch detect.Types {
			case Confusion:
				p := ks.getPodFromLabels(ns, job.Spec.Selector.MatchLabels)

				vList := ks.podAnalyze(job.Spec.Template.Spec, rv, ns, p.Name)

				if len(vList) > 1 {
					severity := "low"
					for _, v := range vList {
						if config.SeverityMap[severity] < config.SeverityMap[v.Severity] {
							severity = v.Severity
						}
					}

					if severity == "low" {
						return nil
					}

					th := &threat{
						Param: fmt.Sprintf("Job Name: %s Namespace: %s", job.Name, ns),
						Value: fmt.Sprintf("Job pod name: %s", p.Name),
						Type:  "Job",
						Describe: fmt.Sprintf("Job Command '%s' finds high risk content(score: %.2f bigger than 0.75), "+
							"and has dangerous configurations, considering it as a backdoor.", detect.Plain, detect.Score),
						Severity: severity,
					}

					ks.VulnConfigures = append(ks.VulnConfigures, th)

					ks.addExtraPod(ns, p, vList)
				}

			default:
				// ignore
			}
		}
	}

cronJob:

	cronjobs, err := ks.KClient.
		BatchV1().
		CronJobs(ns).
		List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	for _, cronjob := range cronjobs.Items {
		for _, con := range cronjob.Spec.JobTemplate.Spec.Template.Spec.Containers {
			command := strings.Join(con.Command, " ")
			detect := maliciousContentCheck(command)
			switch detect.Types {
			case Confusion:
				p := ks.getPodFromLabels(ns, cronjob.Spec.JobTemplate.Spec.Selector.MatchLabels)

				vList := ks.podAnalyze(cronjob.Spec.JobTemplate.Spec.Template.Spec, rv, ns, p.Name)

				if len(vList) > 1 {
					severity := "low"
					for _, v := range vList {
						if config.SeverityMap[severity] < config.SeverityMap[v.Severity] {
							severity = v.Severity
						}
					}

					if severity == "low" {
						return nil
					}

					th := &threat{
						Param: fmt.Sprintf("CronJob Name: %s Namespace: %s", cronjob.Name, ns),
						Value: fmt.Sprintf("CronJob pod name: %s", p.Name),
						Type:  "CronJob",
						Describe: fmt.Sprintf("CronJob Command '%s' finds high risk content(score: %.2f bigger than 0.75), "+
							"and has dangerous configurations, considering it as a backdoor.", detect.Plain, detect.Score),
						Severity: severity,
					}

					ks.VulnConfigures = append(ks.VulnConfigures, th)

					ks.addExtraPod(ns, p, vList)
				}

			default:
				// ignore
			}
		}
	}

	return nil
}

func (ks *KScanner) checkCerts() error {
	log.Printf(config.Yellow("Begin cert analyzing"))

	kubeConfig, err := clientcmd.LoadFromFile("/etc/kubernetes/admin.conf")
	if err != nil {
		if strings.Contains(err.Error(), "no such file or directory") {
			return nil
		}
		return err
	}

	authInfoName := kubeConfig.Contexts[kubeConfig.CurrentContext].AuthInfo
	authInfo := kubeConfig.AuthInfos[authInfoName]
	certs, err := certutil.ParseCertsPEM(authInfo.ClientCertificateData)
	expiration := certs[0].NotAfter

	now := time.Now()

	if expiration.Before(now.AddDate(0, 0, 30)) {
		th := &threat{
			Param:    "Kubernetes certificate expiration",
			Value:    fmt.Sprintf("expire time: %s", expiration.Format("2006-02-01")),
			Type:     "certification",
			Describe: "Your certificate will be expired after 30 days.",
			Severity: "medium",
		}

		ks.VulnConfigures = append(ks.VulnConfigures, th)
	}

	return nil
}

func checkK8sVersion(cli vulnlib.Client, k8sVersion string) (bool, []*threat) {
	var vuln = false

	tlist := []*threat{}

	k, err := version2.NewVersion(k8sVersion)
	if err != nil {
		return vuln, tlist
	}

	// temporarily skip the openshift version detect
	minimumVersion, _ := version2.NewVersion("1.18.0")

	if k.Compare(minimumVersion) <= 0 {
		return vuln, tlist
	}

	rows, err := cli.QueryVulnByName("kubernetes")
	if err != nil {
		log.Printf("faield to search database, error: %v", err)
		return vuln, tlist
	}

	for _, row := range rows {

		if compareVersion(k8sVersion, row.MaxVersion, row.MinVersion) {

			// Skip the Jenkins Kubernetes Plugin vulnerability
			if strings.Contains(row.Description, "Plugin") {
				continue
			}

			th := &threat{
				Param: "kubernetes version",
				Value: k8sVersion,
				Type:  "K8s vulnerable version",
				Describe: fmt.Sprintf("Kubernetes version is suffering the %s vulnerablility "+
					"under the version %s, need to update.", row.CVEID, strings.TrimPrefix(row.MaxVersion, "=")),
				Reference: "Update Kubernetes.",
				Severity:  strings.ToLower(row.Level),
			}

			tlist = append(tlist, th)

			vuln = true
		}
	}

	return vuln, tlist
}
