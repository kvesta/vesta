package cli

import (
	"context"

	"github.com/kvesta/vesta/config"
	"github.com/kvesta/vesta/internal"
	"github.com/spf13/cobra"
)

func analyze() {
	analyzeCmd := &cobra.Command{
		Use: "analyze",
		Short: `Kubernetes and Docker analyze

Examples:
  # analyze Docker
  $ vesta analyze docker

  # Full analyze Kubernetes
  $ vesta analyze k8s

  # analyze by specifying config
  $ vesta analyze k8s --kubeconfig config

  # analyze a special namespace
  $ vesta analyze k8s -n namespace 

  # analyze in a pod
  $ vesta analyze k8s --inside
`}

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
			ctx = context.WithValue(ctx, "inside", inside)

			internal.DoInspectInKubernetes(ctx)
		},
	}

	kubernetesAnalyze.Flags().StringVarP(&nameSpace, "ns", "n", "all", "specific namespace")
	kubernetesAnalyze.Flags().StringVar(&kubeconfig, "kubeconfig", "default", "specific configure file")
	kubernetesAnalyze.Flags().BoolVar(&inside, "inside", false, "running analyze in a pod by using service account token")
	kubernetesAnalyze.Flags().StringVarP(&outfile, "output", "o", "output", "output file location")

	dockerAnalyze.Flags().StringVarP(&outfile, "output", "o", "output", "output file location")

	analyzeCmd.AddCommand(dockerAnalyze)
	analyzeCmd.AddCommand(kubernetesAnalyze)

	rootCmd.AddCommand(analyzeCmd)

}
