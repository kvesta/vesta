package layer

import (
	"archive/tar"
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"time"

	"github.com/kvesta/vesta/pkg"
	"github.com/tidwall/gjson"
)

func md5Stamp() string {
	timeStamp := time.Now().String()
	md5h := md5.Sum([]byte(timeStamp))
	return hex.EncodeToString(md5h[:])
}

func (m *Manifest) GetLayers(ctx context.Context, tarReader *tar.Reader, tempPath string) error {

	manifest, err := pkg.AnalyzeTarLayer(tarReader, tempPath)
	if err != nil {
		return err
	}
	m.Hash = md5Stamp()

	result := gjson.Parse(manifest).Value()

	if result == nil {
		err := errors.New("illegal inspector tar file")
		return err
	}
	value := result.([]interface{})[0].(map[string]interface{})

	// if not contains name, use tar hash
	if value["RepoTags"] == nil {
		m.Name = value["Config"].(string)[:64]
	} else {
		m.Name = value["RepoTags"].([]interface{})[0].(string)
	}

	layers := value["Layers"].([]interface{})
	for _, layer := range layers {
		m.Layers = append(m.Layers, &Layer{
			Hash:       layer.(string)[:64],
			Annotation: "",
		})
	}

	return nil
}
