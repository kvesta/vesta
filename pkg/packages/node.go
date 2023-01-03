package packages

import (
	"fmt"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/tidwall/gjson"
)

type NPM struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Node struct {
	Version string `json:"version"`
	NPMS    []*NPM `json:"NPMS"`
}

func (s *Packages) getNodeModulePacks(nodePath string) error {

	m := s.Mani

	sys := filepath.Join(m.Localpath, nodePath)
	dir, err := ioutil.ReadDir(sys)
	if err != nil {
		return err
	}

	npms, err := getNodeModules(sys, dir)

	node := &Node{
		Version: fmt.Sprintf(`nodejs(%s)`, strings.TrimSuffix(nodePath, "node_modules")),
		NPMS:    npms,
	}

	if strings.Contains(nodePath, "usr/local/lib/node_modules") {
		node.Version = "nodejs (global)"
	}

	s.NodePacks = append(s.NodePacks, node)

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
