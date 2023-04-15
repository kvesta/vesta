package vulnscan

import (
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/kvesta/vesta/config"
)

func sortSeverity(vulnComponents []*vulnComponent) {
	sort.Slice(vulnComponents, func(i, j int) bool {
		return config.SeverityMap[strings.ToLower(vulnComponents[i].Level)] > config.SeverityMap[strings.ToLower(vulnComponents[j].Level)]
	})
}

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

func listPythonSitePack(sitePath string) []string {
	targetPaths := []string{}

	fsys := os.DirFS(sitePath)

	if err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case d.IsDir():
			return nil
		}

		if filepath.Base(path) == "setup.py" || filepath.Base(path) == "__init__.py" {
			targetPaths = append(targetPaths, path)
		}
		return nil

	}); err != nil {
		return targetPaths
	}

	return targetPaths
}

func listPythonPth(sitePath string) []string {
	targetPaths := []string{}
	files, err := ioutil.ReadDir(sitePath)
	if err != nil {
		return targetPaths
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		if filepath.Ext(file.Name()) == ".pth" {
			targetPaths = append(targetPaths, file.Name())
		}
	}

	return targetPaths
}
