package packages

import (
	"context"
	"fmt"
	"github.com/tidwall/gjson"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

type NPM struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Node struct {
	Version string `json:"version"`
	NPMS    []*NPM `json:"NPMS"`
}

func (s *Packages) getNodeModulePacks(ctx context.Context) error {
	m := s.Mani

	var nodePaths = []string{"/usr/local/lib/",
		"/api/vendors", "/var/www/web"}

	for _, p := range nodePaths {
		fsys := filepath.Join(m.Localpath, p, "node_modules")
		dir, err := ioutil.ReadDir(fsys)
		if err != nil {
			continue
		}
		npms, err := getNodeModules(fsys, dir)

		node := &Node{
			Version: fmt.Sprintf(`nodejs("%s")`, p),
			NPMS:    npms,
		}

		if strings.Contains(p, "/usr/local/lib/") {
			node.Version = "nodejs(global)"
		}

		s.NodePacks = append(s.NodePacks, node)

	}

	return nil
}

func getNodeModules(path string, dir []fs.FileInfo) ([]*NPM, error) {
	npms := []*NPM{}

	for _, f := range dir {
		if f.IsDir() {
			jsonFile := filepath.Join(path, f.Name(), "package.json")
			if ok := exists(jsonFile); !ok {
				continue
			}

			moduleFile, err := os.Open(jsonFile)
			if err != nil {
				continue
			}

			data, _ := ioutil.ReadAll(moduleFile)
			version := gjson.Get(string(data), "version")

			npm := &NPM{
				Version: version.String(),
				Name:    f.Name(),
			}

			npms = append(npms, npm)
			moduleFile.Close()
		}

	}

	return npms, nil
}
