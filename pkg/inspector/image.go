package inspector

import (
	"io"
	"log"
	"regexp"
	"strings"

	"github.com/docker/docker/api/types"
	imagev1 "github.com/docker/docker/api/types/image"
	"github.com/kvesta/vesta/config"
)

func (da *DockerApi) GetImageName(imageID string) ([]io.ReadCloser, error) {

	var imageList []string

	images, err := da.DCli.ImageList(ctx, types.ImageListOptions{})
	if err != nil {
		return nil, err
	}

	filter := regexp.MustCompile(`^[a-f0-9]{12}$`)
	if filter.MatchString(imageID) {
		for _, image := range images {
			if len(image.RepoTags) < 1 {
				continue
			}

			sha := strings.Split(image.ID, ":")[1]
			if imageID == sha[:12] {
				imageList = append(imageList, image.RepoTags[0])
			}
		}
	} else {
		imageList = append(imageList, imageID)
	}

	log.Printf(config.Green("Searching for image"))
	fileio, err := da.DCli.ImageSave(ctx, imageList)

	if err != nil {
		return nil, err
	}

	return []io.ReadCloser{fileio}, nil
}

type ImageInfo struct {
	Summary types.ImageSummary
	History []imagev1.HistoryResponseItem
}

func (da *DockerApi) GetAllImage() ([]*ImageInfo, error) {

	images := []*ImageInfo{}
	ims, err := da.DCli.ImageList(ctx, types.ImageListOptions{})

	for _, im := range ims {
		his, err := da.DCli.ImageHistory(ctx, im.ID)
		if err != nil {
			continue
		}

		image := &ImageInfo{
			Summary: im,
			History: his,
		}

		images = append(images, image)
	}

	if err != nil {
		return images, err
	}

	return images, nil
}
