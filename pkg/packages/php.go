package packages

import (
	"errors"
	"github.com/tidwall/gjson"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
)

type PHP struct {
	Name  string     `json:"name"`
	Path  string     `json:"path"`
	Packs []*PHPPack `json:"packs"`
}

type PHPPack struct {
	Name      string `json:"name"`
	Component string `json:"component"`
	Version   string `json:"version"`
}

// Map framework name to standard name
var phpNameMap = map[string]string{"topthink/framework": "thinkphp"}

func getPHPPacks(r io.Reader) (*PHP, error) {
	php := &PHP{}
	phpPacks := []*PHPPack{}

	data, _ := ioutil.ReadAll(r)
	composers := gjson.Get(string(data), "packages").Value()
	if composers != nil {
		packs := composers.([]interface{})
		for _, packIn := range packs {
			pack := packIn.(map[string]interface{})

			phpName := pack["name"].(string)
			if get, ok := phpNameMap[phpName]; ok {
				phpName = get
			} else {
				phpName = filepath.Base(phpName)
			}

			p := &PHPPack{
				Name:      phpName,
				Component: pack["name"].(string),
				Version:   pack["version"].(string),
			}

			phpPacks = append(phpPacks, p)
		}
	}

	php.Packs = phpPacks

	return php, nil
}

func parsePHPName(r io.Reader) string {
	data, _ := ioutil.ReadAll(r)

	composer := gjson.Get(string(data), "name").Value()
	if composer != nil {
		return composer.(string)
	}

	return ""

}

func getWordpressInfo(dir string) (*PHP, error) {

	php := &PHP{
		Name: "wordpress",
	}

	phpPacks := []*PHPPack{}

	wversionReg := regexp.MustCompile(`\$wp_version = '(.*)'`)

	versionPath := filepath.Join(dir, "wp-includes/version.php")
	versionFile, err := os.Open(versionPath)
	if err != nil {
		return php, err
	}
	defer versionFile.Close()

	data, _ := ioutil.ReadAll(versionFile)

	versionMatch := wversionReg.FindStringSubmatch(string(data))

	if len(versionMatch) > 1 {
		p := &PHPPack{
			Name:      "wordpress",
			Component: "wordpress",
			Version:   versionMatch[1],
		}

		phpPacks = append(phpPacks, p)
	}

	// TODO: Get wordpress plugins
	/*
		pluginPath := filepath.Join(dir, "wp-content/plugins")
		fsys := os.DirFS(pluginPath)
		fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
			switch {
			case err != nil:
				return err
			case d.IsDir():
				p := &PHPPack{
					Name: filepath.Base(path),
				}

				phpPacks = append(phpPacks, p)
			}
			return nil
		})
	*/

	if len(phpPacks) < 1 {
		err = errors.New("no wordpress was detected")
		return php, err
	}

	php.Packs = phpPacks

	return php, nil
}
