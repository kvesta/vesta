package cli

import (
	"context"

	"github.com/kvesta/vesta/config"
	"github.com/kvesta/vesta/internal"
	"github.com/spf13/cobra"
)

func analyze() {
	analyzeCmd := &cobra.Command{
		Use:   "analyze",
		Short: `Kubernetes and Docker analyze`,
		Long: `Examples:
  # analyze Docker
  $ vesta analyze docker

  # Full analyze Kubernetes
  $ vesta analyze k8s

  # analyze by specifying config
  $ vesta analyze k8s --kubeconfig config

  # analyze by specifying token
  $ vesta analyze k8s --token <token> --server <SEVER HOST> --insecure

  # analyze all the namespace
  $ vesta analyze k8s -n all

  # analyze a special namespace
  $ vesta analyze k8s -n namespace`}

	dockerAnalyze := &cobra.Command{
		Use:   "docker",
		Short: "analyze docker container",
		Run: func(cmd *cobra.Command, args []string) {
			ctx := config.Ctx
			ctx = context.WithValue(ctx, "output", outfile)

			internal.DoInspectInDocker(ctx)
		},
	}

	kubernetesAnalyze := &cobra.Command{
		Use:   "k8s",
		Short: "analyze configure of kubernetes",
		Run: func(cmd *cobra.Command, args []string) {
			ctx := config.Ctx
			ctx = context.WithValue(ctx, "nameSpace", nameSpace)
			ctx = context.WithValue(ctx, "kubeconfig", kubeconfig)
			ctx = context.WithValue(ctx, "output", outfile)
			ctx = context.WithValue(ctx, "token", bearerToken)
			ctx = context.WithValue(ctx, "server", serverHost)
			ctx = context.WithValue(ctx, "insecure", insecure)

			internal.DoInspectInKubernetes(ctx)
		},
	}

	kubernetesAnalyze.Flags().StringVarP(&nameSpace, "ns", "n", "standard", "specific namespace")
	kubernetesAnalyze.Flags().StringVar(&kubeconfig, "kubeconfig", "default", "specific configure file")
	kubernetesAnalyze.Flags().BoolVar(&insecure, "insecure", false, "skip verify the tls certificate")
	kubernetesAnalyze.Flags().StringVarP(&outfile, "output", "o", "output", "output file location")
	kubernetesAnalyze.Flags().StringVar(&bearerToken, "token", "", "k8s authentication token")
	kubernetesAnalyze.Flags().StringVar(&serverHost, "server", "", "k8s server host")

	dockerAnalyze.Flags().StringVarP(&outfile, "output", "o", "output", "output file location")

	analyzeCmd.AddCommand(dockerAnalyze)
	analyzeCmd.AddCommand(kubernetesAnalyze)

	rootCmd.AddCommand(analyzeCmd)

}
