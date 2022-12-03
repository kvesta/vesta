package packages

import (
	"context"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
)

func (s *Packages) getSpecialPacks(ctx context.Context) error {

	versionReg := regexp.MustCompile(`(\d+\.)?(\d+\.)?(\*|\d+)`)

	m := s.Mani

	slocals := map[string]string{
		"grafana": "usr/share/grafana/VERSION",
	}

	for name, sl := range slocals {
		filePath := filepath.Join(m.Localpath, sl)
		if !exists(filePath) {
			continue
		}

		versionFile, err := os.Open(filePath)
		if err != nil {
			continue
		}

		data, _ := ioutil.ReadAll(versionFile)
		correctVersion := versionReg.FindString(string(data))
		pack := &Package{
			Name:    name,
			Version: correctVersion,
		}

		s.Packs = append(s.Packs, pack)

	}

	return nil
}
