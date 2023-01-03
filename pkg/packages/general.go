package packages

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
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
				return nil
			}

			gobin.Path = path
			s.GOPacks = append(s.GOPacks, gobin)

		}

		return nil
	}); err != nil {
		return err
	}

	return nil
}
