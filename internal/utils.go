package internal

import (
	"context"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/kvesta/vesta/config"
	"github.com/kvesta/vesta/internal/report"
	"github.com/kvesta/vesta/pkg/inspector"
	"github.com/kvesta/vesta/pkg/osrelease"
	"github.com/kvesta/vesta/pkg/packages"
	"github.com/kvesta/vesta/pkg/vulnlib"

	"github.com/docker/docker/client"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

func DoScan(ctx context.Context, tarFile string, tarIO []io.ReadCloser) {

	var wg sync.WaitGroup

	// Get vulnerability database
	if !ctx.Value("skip").(bool) {
		err := vulnlib.Fetch(ctx)
		if err != nil {
			log.Printf("failed to get vulnerability database")
		}
	}

	log.Printf(config.Green("Begin to analyze the layer"))
	// Extract tar file to local folder
	m, err := Extract(ctx, tarFile, tarIO)
	if err != nil {
		log.Printf("Extract container failed, error: %v\n"+
			"\tTips: try to use the container scan", err)
		return
	}

	osVersion, err := osrelease.DetectOs(ctx, *m)
	log.Printf("Detect OS: %s", osVersion.OID)

	vulns := &Vuln{
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

	go func() {
		wg.Add(1)

		defer wg.Done()
		if len(tarIO) > 0 {
			for _, f := range tarIO {
				f.Close()
			}
		}

		// Check directory is legal
		pwd, err := os.Getwd()
		if err != nil {
			log.Printf("failed to remove %s : %v", m.Localpath, err)
		}
		if pwd == m.Localpath {
			return
		}

		err = os.RemoveAll(m.Localpath)
		if err != nil {
			log.Printf("failed to remove %s : %v", m.Localpath, err)
		}
	}()

	err = report.ResolveAnalysisData(ctx, scanner)
	if err != nil {
		log.Printf("report error %v", err)
	}

	err = report.ScanToJson(ctx, scanner)
	if err != nil {
		log.Printf("saving error %v", err)
	}

	wg.Wait()
}

// DoInspectInDocker inspect docker configure
func DoInspectInDocker(ctx context.Context) {

	log.Printf(config.Green("Start analysing"))

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Printf("Cannot initialized docker environment, error: %v", err)
		return
	}

	c := inspector.DockerApi{
		DCli: cli,
	}

	defer c.DCli.Close()

	dockerInps, err := c.GetAllContainers()
	if err != nil {
		if strings.Contains(err.Error(), "Is the docker daemon running") {
			log.Printf("Cannot connect to docker service")
			return
		}
		log.Printf("Cannot get all docker inpector, error: %v", err)
		return
	}

	dockerImages, err := c.GetAllImage()
	if err != nil {
		log.Printf("Cannot get all docker images, error: %v", err)
	}

	engineVersion, err := c.GetEngineVersion(ctx)
	if err != nil {
		log.Printf("Cannot get engine version, error: %v", err)
	}

	serverVersion, err := c.GetDockerServerVersion(ctx)
	if err != nil {
		log.Printf("Cannot get server version, error: %v", err)
	}
	inspects := &Inpsectors{}
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
	var kconfig *restclient.Config
	var err error

	if ctx.Value("kubeconfig") != "default" {
		kubeconfig = ctx.Value("kubeconfig").(string)
	} else if home := homedir.HomeDir(); home != "" {
		kubeconfig = filepath.Join(home, ".kube", "config")
	} else {
		// use original config of kubernetes
		kubeconfig = "/etc/kubernetes/config/admin.conf"
	}

	// use the current context in kubeconfig
	if ctx.Value("inside").(bool) {
		kconfig, err = rest.InClusterConfig()
	} else {
		kconfig, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	}

	if err != nil {
		log.Printf("Cannot initialize kubernetes environment, error: %v", err)
		return
	}

	clientset, err := kubernetes.NewForConfig(kconfig)
	if err != nil {
		log.Printf("Cannot get all kubernetes inpector, error: %v", err)
	}

	inspects := &Inpsectors{}
	scanner := inspects.Kscan
	scanner.KClient = clientset
	scanner.KConfig = kconfig
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
