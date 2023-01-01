package packages

import (
	"debug/buildinfo"
	"io"
	"strings"
)

type MOD struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Version string `json:"version"`
}

type GOBIN struct {
	Name string `json:"name"`
	Path string `json:"path"`
	Deps []*MOD `json:"deps"`
}

func parseGo(r io.ReaderAt) (*GOBIN, error) {
	gobin := &GOBIN{}
	mods := []*MOD{}

	info, err := buildinfo.Read(r)
	if err != nil {
		return gobin, err
	}

	gobin.Name = strings.Split(info.Main.Path, "/")[2]

	for _, dep := range info.Deps {

		if dep.Path == "" || !strings.Contains(dep.Path, "github.com") {
			continue
		}

		modNameArray := strings.Split(dep.Path, "/")
		if len(modNameArray) > 3 {
			// Submodule of the origin module
			continue
		}

		mod := &MOD{
			Name:    modNameArray[2],
			Path:    dep.Path,
			Version: dep.Version,
		}

		mods = append(mods, mod)
	}

	gobin.Deps = mods

	return gobin, nil
}
