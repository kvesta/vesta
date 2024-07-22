package layer

import (
	"archive/tar"
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/image"
	"github.com/kvesta/vesta/pkg"
	_image "github.com/kvesta/vesta/pkg/inspector"
	"github.com/tidwall/gjson"
)

func md5Stamp() string {
	timeStamp := time.Now().String()
	md5h := md5.Sum([]byte(timeStamp))
	return hex.EncodeToString(md5h[:])
}

func (m *Manifest) GetLayers(ctx context.Context, tarReader *tar.Reader, tempPath string) error {

	manifest, histories, err := pkg.AnalyzeTarLayer(tarReader, tempPath)
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
		// Adapter for the new docker image format after Docker Version 25.0.0
		layer = strings.Replace(layer.(string), "blobs/sha256/", "", 1)
		m.Layers = append(m.Layers, &Layer{
			Hash:       layer.(string)[:64],
			Annotation: "",
		})
	}

	// Re-read the history from the manifest.json for the new docker image format
	if strings.HasPrefix(value["Config"].(string), "blobs/sha256/") {
		b, err := os.ReadFile(filepath.Join(tempPath, filepath.Base(value["Config"].(string))+".tar"))
		histories = string(b)
		if err != nil {
			return err
		}
	}

	historyParse := gjson.Get(histories, "history").Value()
	m.Histories = []*_image.ImageInfo{
		{
			Summary: types.ImageSummary{
				ID:       value["Config"].(string)[:64],
				RepoTags: []string{m.Name},
			},
			History: []image.HistoryResponseItem{},
		},
	}
	for _, history := range historyParse.([]interface{}) {
		mapHistory := history.(map[string]interface{})

		pd, _ := time.Parse(time.RFC3339, mapHistory["created"].(string))
		h := image.HistoryResponseItem{
			Created:   pd.Unix(),
			CreatedBy: mapHistory["created_by"].(string),
		}

		if mapHistory["comment"] != nil {
			h.Comment = mapHistory["comment"].(string)
		}

		m.Histories[0].History = append(m.Histories[0].History, h)
	}

	return nil
}
