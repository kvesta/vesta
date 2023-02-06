package packages

import (
	"io"

	"github.com/microsoft/go-rustaudit"
)

type Rust struct {
	Name string   `json:"name"`
	Path string   `json:"path"`
	Deps []*Cargo `json:"deps"`
}

type Cargo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func getRustPacks(rt io.ReaderAt) (*Rust, error) {
	rust := &Rust{}
	deps := []*Cargo{}

	audit, err := rustaudit.GetDependencyInfo(rt)
	if err != nil {
		return rust, err
	}

	for _, dep := range audit.Packages {
		d := &Cargo{
			Name:    dep.Name,
			Version: dep.Version,
		}

		deps = append(deps, d)
	}

	rust.Deps = deps

	return rust, nil
}
