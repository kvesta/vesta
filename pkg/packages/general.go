package packages

import (
	"context"
	"fmt"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func (s *Packages) Traverse(ctx context.Context) error {

	m := s.Mani

	fsys := os.DirFS(m.Localpath)

	if err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case d.IsDir():

			// Get node model
			if strings.HasSuffix(path, "node_modules") && strings.Count(path, "node_modules") < 2 {
				return s.getNodeModulePacks(path)
			}

			// Get wordpress version
			if filepath.Base(path) == "wordpress" && strings.Count(path, "wordpress") < 2 {
				wordPath := filepath.Join(m.Localpath, path)
				wordpress, err := getWordpressInfo(wordPath)
				if err == nil {
					wordpress.Path = path
					s.PHPPacks = append(s.PHPPacks, wordpress)
				}
			}

			// Check python virtual environment and exclude poetry
			if filepath.Base(path) == "site-packages" &&
				!strings.HasPrefix(path, "usr/local/lib") && !strings.Contains(path, "pypoetry") {
				sitePath := filepath.Join(m.Localpath, path)
				pips, err := getLocalPythonPacks(sitePath)
				if err != nil {
					return err
				}

				py := &Python{
					Version:   fmt.Sprintf("python venv path: %s", path),
					SitePacks: pips,
					SitePath:  path,
				}

				s.PythonPacks = append(s.PythonPacks, py)
			}

			// Check special path /var/www/html
			if path == "var/www/html" {
				dirPath := filepath.Join(m.Localpath, path)
				switch getHTMLType(dirPath) {
				case "php":
					wordpress, err := getWordpressInfo(dirPath)
					if err != nil {
						return err
					}
					wordpress.Path = path
					s.PHPPacks = append(s.PHPPacks, wordpress)
				default:
					// ignore
				}
			}

			return nil
		}

		// Parse jar, war
		if strings.HasSuffix(path, ".jar") || strings.HasSuffix(path, ".war") {
			filename := filepath.Join(m.Localpath, path)
			f, err := os.Open(filename)
			if err != nil {
				return nil
			}

			defer f.Close()
			fi, err := f.Stat()
			if err != nil {
				return err
			}

			java, err := getJavaPacks(f, fi.Size())
			if err != nil {
				return err
			}

			java.Path = path
			if java.Name == "" {
				java.Name = filepath.Base(path)
			}
			s.JavaPacks = append(s.JavaPacks, java)

		}

		// Parse PHP composer.lock
		if strings.HasSuffix(path, "composer.lock") {
			filename := filepath.Join(m.Localpath, path)
			f, err := os.Open(filename)
			if err != nil {
				return nil
			}

			defer f.Close()

			php, err := getPHPPacks(f)
			if err != nil {
				return err
			}
			comparePath := filepath.Join(filepath.Dir(filename), "composer.json")
			if exists(comparePath) {
				cf, err := os.Open(comparePath)
				if err == nil {
					defer cf.Close()
					php.Name = parsePHPName(cf)
				}
			}

			if php.Name == "" {
				php.Name = path
			}

			php.Path = path

			s.PHPPacks = append(s.PHPPacks, php)

		}

		// Parse package management of Python poetry
		if strings.HasSuffix(path, "pyproject.toml") {
			filename := filepath.Join(m.Localpath, path)
			py, err := getPyproject(filename)
			if err != nil {
				return nil
			}

			s.PythonPacks = append(s.PythonPacks, py)
		}

		in, err := d.Info()
		if err != nil {
			return nil
		}
		mode := in.Mode()

		if mode.IsRegular() && mode.Perm()&0555 != 0 {
			filename := filepath.Join(m.Localpath, path)
			f, err := os.Open(filename)
			if err != nil {
				return nil
			}

			defer f.Close()

			// Parse go binary
			gobin, err := getGOPacks(f)
			if err != nil {
				goto rustCheck
			}

			gobin.Path = path
			s.GOPacks = append(s.GOPacks, gobin)

		rustCheck:
			rustbin, err := getRustPacks(f)
			if err != nil {
				return nil
			}

			rustbin.Path = path
			s.RustPacks = append(s.RustPacks, rustbin)

		}

		return nil
	}); err != nil {
		return err
	}

	return nil
}

func getHTMLType(path string) string {
	extensions := map[string]int{
		"php": 0,
		"js":  0,
	}

	files, err := ioutil.ReadDir(path)
	if err != nil {
		return ""
	}
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		exSplit := strings.Split(file.Name(), ".")
		if len(exSplit) < 2 {
			continue
		}

		ex := exSplit[len(exSplit)-1]
		if _, ok := extensions[ex]; ok {
			extensions[ex] += 1
		}

	}

	type kv struct {
		Key   string
		Value int
	}

	var exs []kv
	for k, v := range extensions {
		exs = append(exs, kv{k, v})
	}

	sort.Slice(exs, func(i, j int) bool {
		return exs[i].Value > exs[j].Value
	})

	if exs[0].Value > 0 {
		return exs[0].Key
	}

	return ""
}
