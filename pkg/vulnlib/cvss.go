package vulnlib

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tidwall/gjson"
)

const (
	cvssUrl = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-%d.json.gz"

	firstYear = 2002
)

func (c *Client) GetCvss(ctx context.Context) error {

	// Try to delete newest cvss json file and re-download them
	if checkExpired(c.Store) {
		newFile := filepath.Join(c.Store, fmt.Sprintf("nvdcve-1.1-%d.json", time.Now().Year()))
		os.Remove(newFile)
	}

	for y, now := firstYear, time.Now().Year(); y <= now; y++ {
		filename := filepath.Join(c.Store, fmt.Sprintf("nvdcve-1.1-%d.json", y))

		if exists(filename) {
			log.Printf("cvss nvdcve-1.1-%d.json existed", y)
			continue
		}

		url := fmt.Sprintf(cvssUrl, y)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			log.Printf("failed to get url: %s", url)
			continue
		}
		res, err := c.Cli.Do(req)
		if err != nil {
			log.Printf("failed to request url: %s", url)
			continue
		}

		gz, err := gzip.NewReader(res.Body)
		if err != nil {
			continue
		}

		err = store(gz, filename)
		if err != nil {
			gz.Close()
			res.Body.Close()
			return err
		}

		log.Printf("Downloading cvss nvdcve-1.1-%d.json successful", y)
		gz.Close()
		res.Body.Close()
	}

	log.Printf("Downloading cvss file is done")

	// Update cvss data to database
	err := c.cvssToDB()
	if err != nil {
		log.Printf("failed to store cvss")
		return err
	}

	log.Printf("Cvss Storing finished")

	return nil
}

func store(r io.Reader, filename string) error {
	data, err := ioutil.ReadAll(r)
	if err != nil {
		return err
	}

	err = os.WriteFile(filename, data, 0644)
	if err != nil {
		return err
	}
	return nil
}

type cpes struct {
	Name       string
	MaxVersion string
	MinVersion string
	component  string
}

type vuln struct {
	cpe         []*cpes
	score       float64
	level       string
	desc        string
	publishDate string
	cveID       string
	reference   string
	source      string
}

func (c *Client) cvssToDB() error {
	cvssFiles, err := ioutil.ReadDir(c.Store)
	if err != nil {
		log.Printf("failed to list dir '%s'", c.Store)
		return err
	}

	// Optimized update progress
	upToDateFile := filepath.Join(c.Store, fmt.Sprintf("nvdcve-1.1-%d.json", time.Now().Year()))
	logFile := filepath.Join(c.Store, "date.txt")
	if exists(logFile) {
		return c.cvssparse(upToDateFile)
	}

	for _, cf := range cvssFiles {
		if !strings.Contains(cf.Name(), "nvdcve-1.1") {
			continue
		}

		cveFile := filepath.Join(c.Store, cf.Name())
		err = c.cvssparse(cveFile)
		if err != nil {
			log.Printf("%s is stored failed", cf.Name())
			continue
		}
		log.Printf("%s is stored successfully", cf.Name())
	}

	return nil
}

func (c *Client) cvssparse(filename string) error {
	cvFile, err := os.Open(filename)
	if err != nil {
		return err
	}

	defer cvFile.Close()
	value, err := ioutil.ReadAll(cvFile)
	if err != nil {
		return err
	}

	nvd := gjson.Get(string(value), "CVE_Items").Value()
	if nvd == nil {
		return nil
	}

	cveList := nvd.([]interface{})

	for _, cveitems := range cveList {
		cve := cveitems.(map[string]interface{})["cve"].(map[string]interface{})
		cveID := cve["CVE_data_meta"].(map[string]interface{})["ID"].(string)
		if cveID == "" {
			continue
		}
		publishDate := cveitems.(map[string]interface{})["publishedDate"].(string)
		publishDate = strings.Replace(publishDate, "Z", "", -1)
		pd, _ := time.Parse("2006-01-02T15:04", publishDate)
		publishDate = pd.Format("2006-01-02")

		var description string
		descriptionData := cve["description"].(map[string]interface{})["description_data"]
		if descriptionData == nil {
			description = ""
		} else {
			description = descriptionData.([]interface{})[0].(map[string]interface{})["value"].(string)
		}

		cpe := cveitems.(map[string]interface{})["configurations"].(map[string]interface{})["nodes"].([]interface{})
		cpeResult := cpeParse(cpe)

		if len(cpeResult) < 1 {
			continue
		}

		var score float64
		var level string

		if len(cveitems.(map[string]interface{})["impact"].(map[string]interface{})) < 1 {
			continue
		}

		if cveitems.(map[string]interface{})["impact"].(map[string]interface{})["baseMetricV3"] == nil {
			baseMetricV2 := cveitems.(map[string]interface{})["impact"].(map[string]interface{})["baseMetricV2"].(map[string]interface{})
			score = baseMetricV2["cvssV2"].(map[string]interface{})["baseScore"].(float64)
			level = baseMetricV2["severity"].(string)
		} else {
			cvssV3 := cveitems.(map[string]interface{})["impact"].(map[string]interface{})["baseMetricV3"].(map[string]interface{})["cvssV3"].(map[string]interface{})
			score = cvssV3["baseScore"].(float64)
			level = cvssV3["baseSeverity"].(string)
		}

		vulnes := &vuln{
			cpe:         cpeResult,
			score:       score,
			level:       level,
			desc:        description,
			publishDate: publishDate,
			cveID:       cveID,
			source:      "CVSS",
		}

		if vulnes != nil {
			err = c.update(vulnes)
			if err != nil {
				return err
			}
		}

	}

	return nil
}

func cpeParse(cpe []interface{}) []*cpes {
	cs := []*cpes{}
	for index := 0; index < len(cpe); index++ {
		cpeChildren := cpe[index].(map[string]interface{})["children"].([]interface{})
		if len(cpeChildren) > 0 {
			cpeParse(cpeChildren)
		}

		cpeMatch := cpe[index].(map[string]interface{})["cpe_match"].([]interface{})

		isFirst := true
		for _, ci := range cpeMatch {
			c := ci.(map[string]interface{})
			if !c["vulnerable"].(bool) {
				continue
			}
			cpe23 := c["cpe23Uri"].(string)
			cpe23Split := strings.Split(cpe23, ":")

			if i := findName(cs, cpe23Split[4]); i < 0 && !isFirst {
				continue
			} else {
				if i > -1 && cs[i].MinVersion == "0.0" {
					cs[i].MaxVersion = cpe23Split[5]
					continue
				}
			}

			if cpe23Split[10] != "python" && cpe23Split[10] != "node.js" {
				cpe23Split[10] = "*"
			}

			scpe := &cpes{
				Name:       cpe23Split[4],
				MaxVersion: cpe23Split[5],
				MinVersion: "0.0",
				component:  cpe23Split[10],
			}

			if c["versionStartIncluding"] != nil {
				scpe.MinVersion = "=" + c["versionStartIncluding"].(string)
			} else if c["versionStartExcluding"] != nil {
				scpe.MinVersion = c["versionStartExcluding"].(string)
			}

			if c["versionEndIncluding"] != nil {
				scpe.MaxVersion = "=" + c["versionEndIncluding"].(string)
			} else if c["versionEndExcluding"] != nil {
				scpe.MaxVersion = c["versionEndExcluding"].(string)
			}

			cs = append(cs, scpe)
			isFirst = false
		}
	}
	return cs
}

func findName(cpeList []*cpes, name string) int {
	index := -1
	for i, v := range cpeList {
		if v.Name == name {
			return i
		}
	}
	return index
}
