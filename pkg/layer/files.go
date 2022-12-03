package layer

import (
	"bytes"
	"io/fs"
	"os"
)

func (m Manifest) File(file string) (*bytes.Buffer, error) {
	fsys := os.DirFS(m.Localpath)
	buf := []byte{}
	if err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case d.IsDir():
			return nil
		}

		if path == file {
			buf, err = fs.ReadFile(fsys, path)
			if err != nil {
				return err
			}
			return nil
		}

		return nil
	}); err != nil {
		return bytes.NewBuffer(buf), err
	}

	return bytes.NewBuffer(buf), nil
}
