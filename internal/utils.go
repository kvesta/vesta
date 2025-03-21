package internal

import (
	"context"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"

	"github.com/kvesta/vesta/config"
	"github.com/kvesta/vesta/internal/report"
	"github.com/kvesta/vesta/pkg/inspector"
	"github.com/kvesta/vesta/pkg/layer"
	"github.com/kvesta/vesta/pkg/osrelease"
	"github.com/kvesta/vesta/pkg/packages"
	"github.com/kvesta/vesta/pkg/vulnlib"

	"github.com/docker/docker/client"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

func DoScan(ctx context.Context, tarFile string, tarIO []io.ReadCloser) {

	var wg sync.WaitGroup
	var m *layer.Manifest

	// Get vulnerability database
	if !ctx.Value("skip").(bool) {
		err := vulnlib.Fetch(ctx)
		if err != nil {
			log.Printf("failed to get vulnerability database")
		}
	}

	if ctx.Value("tarType").(string) != "filesystem" {
		log.Printf(config.Green("Begin to analyze the layer"))

		// Extract tar file to local folder
		var err error
		m, err = Extract(ctx, tarFile, tarIO)
		if err != nil {
			log.Printf("Extract container failed, error: %v\n"+
				"\tTips: try to use the container scan", err)
			return
		}
	} else {
		// Use path directly
		m = &layer.Manifest{
			Localpath: tarFile,
		}
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

	if ctx.Value("tarType").(string) == "filesystem" {
		goto rep
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

rep:
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
	scanner.DApi = c
	scanner.EngineVersion = engineVersion
	scanner.ServerVersion = serverVersion
	err = scanner.Analyze(ctx)

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

	const tokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"

	// Checking whether inside a pod
	if _, err := os.Stat(tokenFile); os.IsNotExist(err) {
		ctx = context.WithValue(ctx, "inside", false)
	} else {
		ctx = context.WithValue(ctx, "inside", true)
	}

	if ctx.Value("kubeconfig") != "default" {
		kubeconfig = ctx.Value("kubeconfig").(string)
	} else if home := homedir.HomeDir(); home != "" {
		if exists(filepath.Join(home, ".kube", "config")) {
			kubeconfig = filepath.Join(home, ".kube", "config")
		} else if exists("/etc/rancher/k3s/k3s.yaml") {
			// for k3s
			kubeconfig = "/etc/rancher/k3s/k3s.yaml"
		} else if exists("/etc/k0s/k0s.yaml") {
			// for k0s
			kubeconfig = "/etc/k0s/k0s.yaml"
		}

	} else {
		// use original config of kubernetes
		if exists("/etc/kubernetes/config/admin.conf") {
			kubeconfig = "/etc/kubernetes/config/admin.conf"
		} else if exists("/etc/rancher/k3s/k3s.yaml") {
			kubeconfig = "/etc/rancher/k3s/k3s.yaml"
		} else if exists("/etc/k0s/k0s.yaml") {
			kubeconfig = "/etc/k0s/k0s.yaml"
		}

	}

	// Set the server host if exist
	if host := ctx.Value("server").(string); host != "" {
		kconfig, err = clientcmd.BuildConfigFromFlags(host, kubeconfig)
	} else {
		kconfig, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	}

	// Set the insecure method
	if ctx.Value("insecure").(bool) {
		kconfig.Insecure = true
	}

	// Authenticate with token
	if BearerToken := ctx.Value("token").(string); BearerToken != "" {
		kconfig.BearerToken = BearerToken
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
