package packages

import (
	"context"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	pyVersion = regexp.MustCompile(`^python\d+\.\d+$`)
	module    = regexp.MustCompile(`(.*).dist-info`)
)

type PIP struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Python struct {
	Version    string `json:"version"`
	SitePackes []*PIP `json:"SitePackes"`
}

// GetSitePacks get pip installed module. find all installed packs in
// /usr/local/lib/<python-version>/site-packages. list all the `.dist-info`
// directories and parse it. ignore `.egg-info` directories. same as
// `pip freeze`
func (s *Packages) getSitePacks(ctx context.Context) error {
	m := s.Mani
	fsys := filepath.Join(m.Localpath, "usr/local/lib")
	dir, err := ioutil.ReadDir(fsys)
	if err != nil {
		return err
	}
	for _, f := range dir {
		if ok := pyVersion.MatchString(f.Name()); ok {
			path := filepath.Join(fsys, f.Name(), "site-packages")
			if ok := exists(path); !ok {
				path = filepath.Join(fsys, f.Name(), "dist-packages")
				if ok := exists(path); !ok {
					continue
				}
			}
			sitePack, err := getPIPModules(path)
			if err != nil {
				return err
			}
			py := &Python{
				Version:    f.Name(),
				SitePackes: sitePack,
			}
			s.PythonPacks = append(s.PythonPacks, py)
		}
	}
	return nil
}

// getPIPModules get all install module from site-packages
func getPIPModules(path string) ([]*PIP, error) {
	pips := []*PIP{}
	dir, err := ioutil.ReadDir(path)
	if err != nil {
		return nil, err
	}
	for _, f := range dir {
		find := module.FindString(f.Name())
		if find != "" {
			p := parse(f.Name())
			pips = append(pips, p)
		}
	}
	return pips, nil
}

// getLocalPythonPacks for command `pip install packs -t <path>`
func getLocalPythonPacks(path string) ([]*PIP, error) {
	pips := []*PIP{}

	dir, err := ioutil.ReadDir(path)
	if err != nil {
		return pips, err
	}

	for _, f := range dir {
		find := module.FindString(f.Name())
		if find != "" {
			p := parse(f.Name())
			pips = append(pips, p)
		}
	}

	return pips, nil
}

func parse(pathname string) *PIP {
	moduleVersion := strings.Replace(pathname, ".dist-info", "", -1)
	v := strings.Split(moduleVersion, "-")
	p := &PIP{
		Name:    v[0],
		Version: v[1],
	}
	return p
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
