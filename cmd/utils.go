package cmd

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"strings"
	"vesta/config"
	"vesta/internal"
	"vesta/internal/report"
	"vesta/pkg/inspector"
	"vesta/pkg/osrelease"
	"vesta/pkg/packages"
	"vesta/pkg/vulnlib"

	"github.com/docker/docker/client"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

func DoScan(ctx context.Context, tarFile string) {

	// Get vulnerability database
	err := vulnlib.Fetch(ctx)
	if err != nil {
		log.Printf("failed to get vulnerability database")
	}

	log.Printf(config.Green("Begin to analyze the layer"))
	// Extract tar file to local folder
	m, err := Extract(ctx, tarFile)
	if err != nil {
		log.Printf("Extract container failed, error: %v\n"+
			"\tTips: try to use the container scan", err)
		return
	}

	defer func() {
		err := os.RemoveAll(m.Localpath)
		if err != nil {
			log.Printf("failed to remove %s : %v", m.Localpath, err)
		}
	}()
	osVersion, err := osrelease.DetectOs(ctx, *m)

	vulns := &internal.Vuln{
		OsRelease: osVersion,
		Mani:      m,
		Packs: &packages.Packages{
			Mani:      *m,
			OsRelease: *osVersion,
		},
	}

	packs := vulns.Packs
	err = packs.GetApp(ctx)
	if err != nil {
		log.Printf("package error %v", err)
	}

	scanner := vulns.Scan

	err = scanner.Scan(ctx, m, packs)
	if err != nil {
		log.Printf("scan error %v", err)
	}

	err = report.ResolveAnalysisData(ctx, scanner)
	if err != nil {
		log.Printf("report error %v", err)
	}

	err = report.ScanToJson(ctx, scanner)
	if err != nil {
		log.Printf("saving error %v", err)
	}

}

// DoInspectInDocker inspect docker configure
func DoInspectInDocker(ctx context.Context) {

	log.Printf(config.Green("Start analysing"))

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Printf("Can not initialized docker environment, error: %v\n")
		return
	}

	c := inspector.DockerApi{
		DCli: cli,
	}

	defer c.DCli.Close()

	dockerInps, err := c.GetAllContainers()
	if err != nil {
		if strings.Contains(err.Error(), "Is the docker daemon running") {
			log.Printf("Can not connect to docker service")
			return
		}
		log.Printf("Can not get all docker inpector, error: %v", err)
		return
	}

	dockerImages, err := c.GetAllImage()
	if err != nil {
		log.Printf("Can not get all docker images, error: %v", err)
	}

	engineVersion, err := c.GetEngineVersion(ctx)
	if err != nil {
		log.Printf("Can not get engine version, error: %v", err)
	}

	serverVersion, err := c.GetDockerServerVersion(ctx)
	if err != nil {
		log.Printf("Can not get server version, error: %v", err)
	}
	inspects := &internal.Inpsectors{}
	scanner := inspects.Scan
	scanner.EngineVersion = engineVersion
	scanner.ServerVersion = serverVersion
	err = scanner.Analyze(ctx, dockerInps, dockerImages)

	if err != nil {
		log.Printf("Snalyze error %v", err)
		return
	}

	err = report.ResolveDockerData(ctx, scanner)
	if err != nil {
		log.Printf("Report error %v", err)
	}

	err = report.AnalyzeDockerToJson(ctx, scanner)
	if err != nil {
		log.Printf("Saving error %v", err)
	}

}

// DoInspectInKubernetes inspect kubernetes' configure
func DoInspectInKubernetes(ctx context.Context) {

	log.Printf(config.Green("Start analysing"))

	var kubeconfig string

	if ctx.Value("kubeconfig") != "default" {
		kubeconfig = ctx.Value("kubeconfig").(string)
	} else if home := homedir.HomeDir(); home != "" {
		kubeconfig = filepath.Join(home, ".kube", "config")
	} else {
		// use original config of kubernetes
		kubeconfig = "/etc/kubernetes/config/admin.conf"
	}

	// use the current context in kubeconfig
	kconfig, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		log.Printf("Can not initialize kubernetes environment, error: %v", err)
		return
	}

	clientset, err := kubernetes.NewForConfig(kconfig)
	if err != nil {
		log.Printf("Can not get all kubernetes inpector, error: %v", err)
	}

	inspects := &internal.Inpsectors{}
	scanner := inspects.Kscan
	scanner.KClient = clientset
	err = scanner.Kanalyze(ctx)

	if err != nil {
		log.Printf("Analyze error")
	}

	err = report.ResolveKuberData(ctx, scanner)
	if err != nil {
		log.Printf("Report error %v", err)
	}

	err = report.AnalyzeKubernetesToJson(ctx, scanner)
	if err != nil {
		log.Printf("Saving error %v", err)
	}
}
