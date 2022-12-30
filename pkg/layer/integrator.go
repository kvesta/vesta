package layer

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tidwall/gjson"
)

func getManifest(dir string) string {
	fsys := os.DirFS(dir)
	buf := []byte{}
	if err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case d.IsDir():
			return nil
		}

		if strings.Contains(path, "manifest.json") {
			buf, err = fs.ReadFile(fsys, path)
			if err != nil {
				return err
			}

			return nil
		}

		return nil
	}); err != nil {
		return ""
	}

	return string(buf)
}

func md5Stamp() string {
	timeStamp := time.Now().String()
	md5h := md5.Sum([]byte(timeStamp))
	return hex.EncodeToString(md5h[:])
}

func (m *Manifest) GetLayers(ctx context.Context, tempPath string) error {

	manifest := getManifest(tempPath)
	m.Hash = md5Stamp()

	result := gjson.Parse(manifest).Value()

	if result == nil {
		err := errors.New("illegal inspector tar file")
		return err
	}
	value := result.([]interface{})[0].(map[string]interface{})
	cwd, _ := os.Getwd()

	// if not contains name, use tar hash
	if value["RepoTags"] == nil {
		m.Name = value["Config"].(string)[:64]
	} else {
		m.Name = value["RepoTags"].([]interface{})[0].(string)
	}
	m.Localpath = filepath.Join(cwd, m.Hash)

	layers := value["Layers"].([]interface{})
	for _, layer := range layers {
		m.Layers = append(m.Layers, &Layer{
			Hash:       layer.(string)[:64],
			Annotation: "",
			localpath:  filepath.Join(tempPath, layer.(string)[:64]),
		})
	}

	return nil
}
