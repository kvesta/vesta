package cli

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"

	_cmd "github.com/kvesta/vesta/cmd"
	"github.com/kvesta/vesta/config"
	"github.com/kvesta/vesta/pkg/inspector"
	"github.com/kvesta/vesta/pkg/vulnlib"

	"github.com/spf13/cobra"
)

var (
	rootCmd = &cobra.Command{
		Use:   "vesta [OPTIONS]",
		Short: "Docker and Kubernetes analysis",
		Long: `Vesta is a static analysis of vulnerabilities, Docker and Kubernetes configuration detect toolkit
               Tutorial is available at https://github.com/kvesta/vesta`,
	}

	tarFile    string
	nameSpace  string
	kubeconfig string
	outfile    string
	upgradeall bool
)

func Execute() error {
	scanCmd := &cobra.Command{
		Use:   "scan [OPTIONS]",
		Short: "Container scan",
	}

	analyzeCmd := &cobra.Command{
		Use:   "analyze",
		Short: "Kubernetes analyze",
	}

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information and qui",
		Args:  NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(versions)
		},
	}

	// Upgrade vulnerability database
	dataupgradeCmd := &cobra.Command{
		Use:   "upgrade",
		Short: "Upgrade vulnerability database",
		Args:  NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			ctx := config.Ctx
			ctx = context.WithValue(ctx, "reset", upgradeall)

			err := vulnlib.Fetch(ctx)
			if err != nil {
				log.Printf("Upgrading vulnerability database failed, error: %v", err)
			}

			log.Printf("Upgrading vulnerability database success")
		},
	}

	dockerAnalyze := &cobra.Command{
		Use:   "docker",
		Short: "analyze docker container",
		Run: func(cmd *cobra.Command, args []string) {
			ctx := config.Ctx
			ctx = context.WithValue(ctx, "output", outfile)

			_cmd.DoInspectInDocker(ctx)
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

			_cmd.DoInspectInKubernetes(ctx)
		},
	}

	imageCheck := &cobra.Command{
		Use:   "image",
		Short: "input from image",
		Run: func(cmd *cobra.Command, args []string) {
			ctx := config.Ctx
			ctx = context.WithValue(ctx, "tarType", "image")
			ctx = context.WithValue(ctx, "output", outfile)

			if tarFile == "" {
				var err error
				tarFile, err = inspector.GetTarFromID(ctx, args[0])

				if err != nil {
					os.Exit(1)
				}

				defer func() {
					pwd, _ := os.Getwd()
					if tarFile == filepath.Join(pwd, "output.tar") {
						err := os.RemoveAll(tarFile)
						if err != nil {
							log.Printf("failed to remove %s : %v", tarFile, err)
						}
					}
				}()

			}

			if tarFile == "" {
				log.Printf("Can not get tarfile parameter. " +
					"Make sure that you have a right image ID " +
					"or use -f to get from tar file")
				return
			}
			_cmd.DoScan(ctx, tarFile)
		},
	}

	containerCheck := &cobra.Command{
		Use:   "container",
		Short: "input from inspector",
		Run: func(cmd *cobra.Command, args []string) {
			ctx := config.Ctx
			ctx = context.WithValue(ctx, "tarType", "container")
			ctx = context.WithValue(ctx, "output", outfile)

			if tarFile == "" {
				var err error
				tarFile, err = inspector.GetTarFromID(ctx, args[0])

				if err != nil {
					os.Exit(1)
				}

				defer func() {
					pwd, _ := os.Getwd()
					if tarFile == filepath.Join(pwd, "output.tar") {
						err := os.RemoveAll(tarFile)
						if err != nil {
							log.Printf("failed to remove %s : %v", tarFile, err)
						}
					}
				}()
			}

			if tarFile == "" {
				log.Printf("Can not get tarfile parameter. " +
					"Make sure that you have a right container ID" +
					"or use -f to get from tar file")
				return
			}
			_cmd.DoScan(ctx, tarFile)
		},
	}

	imageCheck.Flags().StringVarP(&tarFile, "file", "f", "", "path of tar file")
	imageCheck.Flags().StringVarP(&outfile, "output", "o", "output", "output file location")

	containerCheck.Flags().StringVarP(&tarFile, "file", "f", "", "path of tar file")
	containerCheck.Flags().StringVarP(&outfile, "output", "o", "output", "output file location")

	kubernetesAnalyze.Flags().StringVarP(&nameSpace, "ns", "n", "all", "specific namespace")
	kubernetesAnalyze.Flags().StringVar(&kubeconfig, "kubeconfig", "default", "specific configure file")
	kubernetesAnalyze.Flags().StringVarP(&outfile, "output", "o", "output", "output file location")

	dockerAnalyze.Flags().StringVarP(&outfile, "output", "o", "output", "output file location")

	dataupgradeCmd.Flags().BoolVarP(&upgradeall, "all", "a", false, "Reset the database")

	scanCmd.AddCommand(imageCheck)
	scanCmd.AddCommand(containerCheck)

	analyzeCmd.AddCommand(dockerAnalyze)
	analyzeCmd.AddCommand(kubernetesAnalyze)

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(analyzeCmd)
	rootCmd.AddCommand(dataupgradeCmd)
	rootCmd.AddCommand(versionCmd)
	return rootCmd.Execute()
}
