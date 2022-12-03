package pkg

import (
	"archive/tar"
	"io"
	"log"
	"os"
	"path/filepath"
)

func exists(path string) bool {
	_, err := os.Stat(path)
	if err != nil {
		if os.IsExist(err) {
			return true
		}

		return false
	}
	return true
}

func Decompress(tarReader *tar.Reader, path string) error {
	for hdr, err := tarReader.Next(); err != io.EOF; hdr, err = tarReader.Next() {
		if err != nil {
			return err
		}

		extractFile := filepath.Join(path, hdr.Name)
		switch hdr.Typeflag {
		case tar.TypeDir:
			if !exists(extractFile) {
				if err := os.MkdirAll(extractFile, 0775); err != nil {
					return err
				}
			}
		case tar.TypeReg:
			file, err := os.OpenFile(extractFile, os.O_CREATE|os.O_RDWR, os.FileMode(hdr.Mode))
			if err != nil {
				//log.Printf("file %s can not create: %v", hdr.Name, err)
				continue
			}
			_, err = io.Copy(file, tarReader)
			if err != nil {
				log.Printf("file %s can not extract: %v", hdr.Name, err)
			}
		}
	}
	return nil
}
