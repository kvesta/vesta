package cli

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/kvesta/vesta/config"
	"github.com/kvesta/vesta/internal"
	"github.com/kvesta/vesta/pkg/inspector"
	"github.com/spf13/cobra"
)

func scan() {
	scanCmd := &cobra.Command{
		Use:   "scan [OPTIONS]",
		Short: `Container scan`,
		Long: `Examples:
  # Scan a container image
  $ vesta scan image nginx:latest

  # Scan a container image with specific host
  $ DOCKER_HOST=<DOCKER host> vesta scan image nginx:latest

  # Scan a container image from a tar archive
  $ vesta scan image -f python.tar
 
  # Scan a running container
  $ vesta scan container nginx1

  # Scan a exported container from a tar archive
  $ vesta scan container -f nginx.tar`}

	imageCheck := &cobra.Command{
		Use:   "image",
		Short: "input from image",
		Run: func(cmd *cobra.Command, args []string) {

			ctx := config.Ctx
			ctx = context.WithValue(ctx, "tarType", "image")
			ctx = context.WithValue(ctx, "output", outfile)
			ctx = context.WithValue(ctx, "skip", skipUpdate)

			if len(args) < 1 && tarFile == "" {
				fmt.Println("Require at least 1 argument.")
				os.Exit(1)
			}

			var tarIO []io.ReadCloser

			if tarFile == "" {
				var err error
				tarIO, err = inspector.GetTarFromID(ctx, args[0])

				if err != nil {
					os.Exit(1)
				}

			}

			if tarFile == "" && len(tarIO) < 1 {
				log.Printf("Cannot get tarfile. " +
					"Make sure that you have the right image ID " +
					"or use -f to get from tar file")
				return
			}
			internal.DoScan(ctx, tarFile, tarIO)
		},
	}

	containerCheck := &cobra.Command{
		Use:   "container",
		Short: "input from inspector",
		Run: func(cmd *cobra.Command, args []string) {

			ctx := config.Ctx
			ctx = context.WithValue(ctx, "tarType", "container")
			ctx = context.WithValue(ctx, "output", outfile)
			ctx = context.WithValue(ctx, "skip", skipUpdate)

			if len(args) < 1 && tarFile == "" {
				fmt.Println("Require at least 1 argument.")
				os.Exit(1)
			}

			var tarIO []io.ReadCloser

			if tarFile == "" {
				var err error
				tarIO, err = inspector.GetTarFromID(ctx, args[0])

				if err != nil {
					os.Exit(1)
				}

			}

			if tarFile == "" && len(tarIO) < 1 {
				log.Printf("Cannot get tarfile. " +
					"Make sure that you have the right container ID" +
					"or use -f to get from tar file")
				return
			}

			internal.DoScan(ctx, tarFile, tarIO)
		},
	}

	imageCheck.Flags().StringVarP(&tarFile, "file", "f", "", "path of tar file")
	imageCheck.Flags().StringVarP(&outfile, "output", "o", "output", "output file location")
	imageCheck.Flags().BoolVar(&skipUpdate, "skip", false, "skip the updating")

	containerCheck.Flags().StringVarP(&tarFile, "file", "f", "", "path of tar file")
	containerCheck.Flags().StringVarP(&outfile, "output", "o", "output", "output file location")
	containerCheck.Flags().BoolVar(&skipUpdate, "skip", false, "skip the updating")

	scanCmd.AddCommand(imageCheck)
	scanCmd.AddCommand(containerCheck)

	rootCmd.AddCommand(scanCmd)

}
