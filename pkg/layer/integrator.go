package layer

import (
	"archive/tar"
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/tidwall/gjson"
)

func getManifest(fd *os.File) string {
	tarReader := tar.NewReader(fd)
	for hdr, err := tarReader.Next(); err != io.EOF; hdr, err = tarReader.Next() {
		if err != nil {
			return ""
		}

		if hdr.Name == "manifest.json" {
			content := strings.Builder{}
			_, err := io.Copy(&content, tarReader)
			if err != nil {
				return ""
			}

			return content.String()

		}
	}
	return ""
}

func calMd5(fd *os.File) string {
	md5h := md5.New()
	_, err := io.Copy(md5h, fd)
	if err != nil {
		log.Printf("io copy error, error: %v", err)
		return ""
	}
	return hex.EncodeToString(md5h.Sum(nil))
}

func (m *Manifest) GetLayers(ctx context.Context, imagePath, tempPath string) error {
	fd, err := os.Open(imagePath)
	if err != nil {
		log.Printf("open tar file failed")
		return err
	}

	defer fd.Close()
	manifest := getManifest(fd)
	result := gjson.Parse(manifest).Value()

	if result == nil {
		err = errors.New("illegal inspector tar file")
		return err
	}
	value := result.([]interface{})[0].(map[string]interface{})
	cwd, _ := os.Getwd()
	m.Hash = calMd5(fd)
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

	//log.Printf("Getting layers successful")

	return nil
}
