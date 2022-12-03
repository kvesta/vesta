package inspector

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/kvesta/vesta/config"

	"github.com/docker/docker/api/types"
)

func (da *DockerApi) GetImageName(imageID string) (string, error) {

	var imageList []string

	images, err := da.DCli.ImageList(ctx, types.ImageListOptions{})
	if err != nil {
		return "", err
	}

	// Do not use the `all` option temporary
	if strings.ToLower(imageID) == "all" {
		for _, image := range images {
			if len(image.RepoTags) < 1 {
				continue
			}
			imageList = append(imageList, image.RepoTags[0])
		}
	} else {
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
	}

	log.Printf(config.Green("Searching image"))
	fileio, err := da.DCli.ImageSave(ctx, imageList)

	if err != nil {
		return "", err
	}
	pwd, _ := os.Getwd()
	tarFile := filepath.Join(pwd, "output.tar")
	file, _ := os.OpenFile(tarFile, os.O_CREATE|os.O_RDWR, 0666)

	_, err = io.Copy(file, fileio)
	if err != nil {
		return "", err
	}

	return tarFile, nil
}

func (da *DockerApi) GetAllImage() ([]types.ImageSummary, error) {

	var images []types.ImageSummary

	images, err := da.DCli.ImageList(ctx, types.ImageListOptions{})
	if err != nil {
		return images, err
	}

	return images, nil
}
