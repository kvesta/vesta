package report

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/kvesta/vesta/config"
	"github.com/kvesta/vesta/internal/analyzer"
	"github.com/kvesta/vesta/internal/vulnscan"

	"k8s.io/apimachinery/pkg/util/json"
)

func exists(path string) bool {
	_, err := os.Stat(path)
	if err != nil {
		if os.IsExist(err) {
			return true
		}

		return false
	}
	return true
}

func getOutputFile(ctx context.Context) (string, error) {
	outfile := ctx.Value("output").(string)
	if outfile == "output" {
		pwd, _ := os.Getwd()
		folder := filepath.Join(pwd, "output")
		if !exists(folder) {
			err := os.MkdirAll(folder, os.FileMode(0755))
			if err != nil {
				return "", err
			}
		}
		nowStamp := time.Now().Format("2006-01-02")
		file := filepath.Join(folder, fmt.Sprintf("%s.json", nowStamp))

		return file, nil

	} else {
		folder := filepath.Dir(outfile)
		if !exists(folder) {
			err := os.MkdirAll(folder, os.FileMode(0755))
			if err != nil {
				return "", err
			}
		}

		return outfile, nil

	}

}

func ScanToJson(ctx context.Context, r vulnscan.Scanner) error {
	filename, err := getOutputFile(ctx)
	if err != nil {
		return err
	}

	data, err := json.Marshal(r.Vulns)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(filename, data, 0644)
	if err != nil {
		return err
	}

	fmt.Printf("\n")
	log.Printf("Output file is saved in: %s", config.Yellow(filename))

	return nil
}

func AnalyzeDockerToJson(ctx context.Context, r analyzer.Scanner) error {
	filename, err := getOutputFile(ctx)
	if err != nil {
		return err
	}

	data, err := json.Marshal(r.VulnContainers)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(filename, data, 0644)
	if err != nil {
		return err
	}

	fmt.Printf("\n")
	log.Printf("Output file is saved in: %s", config.Yellow(filename))

	return nil
}

func AnalyzeKubernetesToJson(ctx context.Context, r analyzer.KScanner) error {

	filename, err := getOutputFile(ctx)
	if err != nil {
		return err
	}

	var f *os.File
	if !exists(filename) {
		f, err = os.Create(filename)
	} else {
		f, err = os.OpenFile(filename, os.O_WRONLY, 0644)
	}

	if err != nil {
		return err
	}

	defer f.Close()

	dataPods, err := json.Marshal(r.VulnContainers)
	if err != nil {
		return err
	}

	_, err = f.Write(dataPods)
	if err != nil {
		return err
	}

	dataConfig, err := json.Marshal(r.VulnConfigures)

	_, err = f.Write(dataConfig)
	if err != nil {
		return err
	}

	fmt.Printf("\n")
	log.Printf("Output file is saved in: %s", config.Yellow(filename))

	return nil
}
