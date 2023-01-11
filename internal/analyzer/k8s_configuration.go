package analyzer

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"time"

	"github.com/docker/docker/client"
	"github.com/kvesta/vesta/config"
	"github.com/kvesta/vesta/pkg/inspector"
	"github.com/kvesta/vesta/pkg/vulnlib"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"
	certutil "k8s.io/client-go/util/cert"
)

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
	if ok, tlist := checkKernelVersion(vulnCli); ok {
		ks.VulnConfigures = append(ks.VulnConfigures, tlist...)
	}

	// Check Docker server version
	if ok, tlist := checkDockerVersion(vulnCli, serverVersion); ok {
		ks.VulnConfigures = append(ks.VulnConfigures, tlist...)
	}

	return nil
}

func (ks *KScanner) checkPersistentVolume() error {
	log.Printf(config.Yellow("Begin PV and PVC analyzing"))

	tlist := []*threat{}
	pvs, err := ks.KClient.CoreV1().PersistentVolumes().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		log.Printf("list persistentvolumes failed: %v", err)
		return err
	}
	for _, pv := range pvs.Items {

		// Check whether using the host mount
		if pv.Spec.HostPath == nil {
			continue
		}

		pvPath := filepath.Dir(pv.Spec.HostPath.Path)

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

// checkPod check pod privileged and configure of server account
func (ks *KScanner) checkPod(ns string) error {
	if ns == "kubernetes-dashboard" {
		return ks.checkKuberDashboard()
	}

	pods, err := ks.KClient.CoreV1().Pods(ns).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	for _, pod := range pods.Items {

		vList := []*threat{}

		// Skip pod which is not running
		if pod.Status.Phase != "Running" {
			continue
		}

		for _, v := range pod.Spec.Volumes {
			if ok, tlist := checkPodVolume(v); ok {
				vList = append(vList, tlist...)
			}
		}

		for _, sp := range pod.Spec.Containers {

			// Skip some sidecars
			if sp.Name == "istio-proxy" {
				// Try to check the istio header `X-Envoy-Peer-Metadata`
				// reference: https://github.com/istio/istio/issues/17635
				if ok, tlist := ks.checkIstioHeader(pod.Name, ns, pod.Spec.Containers[0].Name); ok {
					vList = append(vList, tlist...)
				}

				continue
			}

			if ok, tlist := checkPodPrivileged(sp); ok {
				vList = append(vList, tlist...)
			}

			if ok, tlist := checkPodAccountService(sp); ok {
				vList = append(vList, tlist...)
			}

			if ok, tlist := checkResourcesLimits(sp); ok {
				vList = append(vList, tlist...)
			}

		}

		if len(vList) > 0 {

			sortSeverity(vList)
			con := &container{
				ContainerName: pod.Name,
				Namepsace:     ns,
				Threats:       vList,
			}
			ks.VulnContainers = append(ks.VulnContainers, con)
		}

	}

	return nil
}

// checkJobsOrCornJob check job and cronjob whether have malicious command
func (ks *KScanner) checkJobsOrCornJob(ns string) error {
	jobs, err := ks.KClient.BatchV1().Jobs(ns).List(context.TODO(), metav1.ListOptions{})

	if err != nil {
		return err
	}

	cronjobs, err := ks.KClient.BatchV1().CronJobs(ns).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	for _, job := range jobs.Items {
		seccompProfile := job.Spec.Template.Spec.SecurityContext.SeccompProfile
		selinuxProfile := job.Spec.Template.Spec.SecurityContext.SELinuxOptions
		if job.Status.Active == 1 &&
			seccompProfile == nil && selinuxProfile == nil {
			command := strings.Join(job.Spec.Template.Spec.Containers[0].Command, " ")
			if len(command) > 50 {
				command = command[:50] + "..."
			}

			th := &threat{
				Type:     "Job",
				Param:    fmt.Sprintf("Job Name: %s\nNamespace: %s", job.Name, ns),
				Value:    fmt.Sprintf("Command: %s", command),
				Describe: fmt.Sprintf("Active job %s is not setting any security policy.", job.Name),
				Severity: "low",
			}

			ks.VulnConfigures = append(ks.VulnConfigures, th)
		}
	}

	for _, cronjob := range cronjobs.Items {
		seccompProfile := cronjob.Spec.JobTemplate.Spec.Template.Spec.SecurityContext.SeccompProfile
		selinuxProfile := cronjob.Spec.JobTemplate.Spec.Template.Spec.SecurityContext.SELinuxOptions
		if seccompProfile == nil && selinuxProfile == nil {

			command := strings.Join(cronjob.Spec.JobTemplate.Spec.Template.Spec.Containers[0].Command, " ")
			if len(command) > 50 {
				command = command[:50] + "..."
			}

			th := &threat{
				Type: "CronJob",
				Param: fmt.Sprintf("CronJob Name: %s\nNamespace: %s\n"+
					"Schedule: %s", cronjob.Name, ns, cronjob.Spec.Schedule),
				Value:    fmt.Sprintf("Command: %s", command),
				Describe: fmt.Sprintf("Active Cronjob %s is not setting any security policy.", cronjob.Name),
				Severity: "low",
			}

			ks.VulnConfigures = append(ks.VulnConfigures, th)
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
