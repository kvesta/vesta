package packages

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
)

func (s *Packages) Traverse(ctx context.Context) error {

	m := s.Mani

	fsys := os.DirFS(m.Localpath)

	if err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case d.IsDir():
			return nil
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

			// parse go binary
			gobin, err := parseGo(f)
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
