package layer

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"vesta/pkg"
)

type Layer struct {
	Hash       string `json:"hash"`
	Annotation string `json:"path"`

	localpath string `json:"local"`
}

// for another scan method
// GetTarFile get file from every layer tar
func (l *Layer) GetTarFile(file string) (*bytes.Buffer, error) {
	buf := bytes.NewBuffer([]byte{})

	filePath := filepath.Join(l.Hash, "layer.tar")
	image, err := os.Open(filePath)
	if err != nil {
		return buf, err
	}

	defer image.Close()
	tarReader := tar.NewReader(image)
	for hdr, err := tarReader.Next(); err != io.EOF; hdr, err = tarReader.Next() {
		if err != nil {
			return nil, err
		}

		if file == hdr.Name {
			_, err := io.Copy(buf, tarReader)
			if err != nil {
				return nil, err
			}

			return buf, nil
		}
	}
	return buf, nil
}

func (l *Layer) Integration(dir string) error {
	targetFile := filepath.Join(l.localpath, "layer.tar")

	if runtime.GOOS == "windows" {
		image, err := os.Open(targetFile)

		if err != nil {
			return err
		}

		defer image.Close()
		tarReader := tar.NewReader(image)
		err = pkg.Decompress(tarReader, dir)
		if err != nil {
			return fmt.Errorf("err: %v", err)
		}

	} else {
		tarcmd := exec.Command("tar", "--no-same-owner", "-xC", dir, "-f", targetFile)
		if err := tarcmd.Run(); err != nil {
			return fmt.Errorf("err: %v", err)
		}

		chmodcmd := exec.Command("chmod", "-R", "u+w", dir)
		if err := chmodcmd.Run(); err != nil {
			return fmt.Errorf("err: %v", err)
		}
	}

	return nil
}
