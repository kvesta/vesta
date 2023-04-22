package vulnlib

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/tidwall/gjson"
)

const (
	OSCSUrl     = "https://www.oscs1024.com/oscs/v1/intelligence/list"
	OSCSVulnUrl = "https://www.oscs1024.com/oscs/v1/vdb/info"

	pageSize = 50
)

func (c *Client) GetOSCS(ctx context.Context) error {

	page := 1

	resBody, err := oscsRequest(c.Cli, page)
	if err != nil {
		return err
	}

	oscsData := gjson.Parse(string(resBody)).Value()
	oscsVuln := oscsData.(map[string]interface{})["data"]
	if oscsVuln == nil {
		err = errors.New("no oscs data")
		return err
	}

	err = c.oscsParse(oscsVuln)
	if err != nil {
		return err
	}

	if checkExpired(c.Store) {
		return nil
	}

	total := oscsVuln.(map[string]interface{})["total"].(float64)
	totalPages := int(total) / pageSize

	page += 1
	for page <= totalPages {

		resBody, err = oscsRequest(c.Cli, page)
		if err != nil {
			return err
		}

		oscsData = gjson.Parse(string(resBody)).Value()
		oscsVuln = oscsData.(map[string]interface{})["data"]
		if oscsVuln == nil {
			err = errors.New("no oscs data")
			return err
		}

		err = c.oscsParse(oscsVuln)
		if err != nil {
			return err
		}

		page += 1
	}

	log.Printf("OSCS updating finish")

	return nil
}

func oscsRequest(cli *http.Client, page int) ([]byte, error) {
	resBody := []byte{}

	jsonPost := map[string]interface{}{
		"page":     page,
		"per_page": pageSize,
	}

	data, _ := json.Marshal(jsonPost)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, OSCSUrl, bytes.NewBuffer(data))
	if err != nil {
		return resBody, err
	}

	req.Header.Set("Referer", "https://www.oscs1024.com/cm")
	req.Header.Set("Origin", "https://www.oscs1024.com")
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	res, err := cli.Do(req)
	if err != nil {
		log.Printf("failed to request url: %s", OSCSUrl)
	}

	defer req.Body.Close()

	resBody, err = ioutil.ReadAll(res.Body)
	if err != nil {
		return resBody, err
	}

	return resBody, nil
}

func (c *Client) oscsVulnParse(mps string) ([]byte, error) {
	resBody := []byte{}

	jsonPost := map[string]interface{}{
		"vuln_no": mps,
	}

	data, _ := json.Marshal(jsonPost)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, OSCSVulnUrl, bytes.NewBuffer(data))
	if err != nil {
		return resBody, err
	}

	req.Header.Set("Referer", "https://www.oscs1024.com/cm")
	req.Header.Set("Origin", "https://www.oscs1024.com")
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")

	res, err := c.Cli.Do(req)
	if err != nil {
		return resBody, err
	}

	defer res.Body.Close()

	resBody, err = ioutil.ReadAll(res.Body)
	if err != nil {
		return resBody, err
	}

	return resBody, nil
}

func (c *Client) oscsParse(data interface{}) error {
	valueData := data.(map[string]interface{})["data"]
	if valueData == nil {
		err := errors.New("no oscs data")
		return err
	}

	for _, pro := range valueData.([]interface{}) {
		proMap := pro.(map[string]interface{})
		if proMap == nil {
			continue
		}

		if int(proMap["intelligence_type"].(float64)) == 3 {
			err := c.oscsToDB(proMap)
			if err != nil {
				log.Printf("failed to store oscs db, error: %v", err)
				return err
			}
		}
	}

	return nil
}

func (c *Client) oscsToDB(com map[string]interface{}) error {
	title := com["title"].(string)
	characterRegex := regexp.MustCompile(`[\w-@/]+`)
	characterMatch := characterRegex.FindAllStringSubmatch(title, -1)

	if len(characterMatch) < 2 {
		return nil
	}

	pd, _ := time.Parse(time.RFC3339, com["public_time"].(string))
	publishDate := pd.Format("2006-01-02")

	var cpe []*cpes
	vulnes := &vuln{
		score:       8.5,
		level:       "high",
		publishDate: publishDate,
		cveID:       com["mps"].(string),
		source:      "OSCS",
	}

	switch {
	case strings.ToUpper(characterMatch[0][0]) == "NPM":
		cpe = []*cpes{
			{
				Name:       characterMatch[1][0],
				MaxVersion: "999",
				MinVersion: "0.0",
				component:  "node.js",
			},
		}

	case strings.ToUpper(characterMatch[1][0]) == "NPM":
		cpe = []*cpes{
			{
				Name:       characterMatch[0][0],
				MaxVersion: "999",
				MinVersion: "0.0",
				component:  "node.js",
			},
		}

	case characterMatch[0][0] == "PyPi":
		cpe = []*cpes{
			{
				Name:       characterMatch[1][0],
				MaxVersion: "999",
				MinVersion: "0.0",
				component:  "python",
			},
		}

	case characterMatch[1][0] == "Python":
		cpe = []*cpes{
			{
				Name:       characterMatch[0][0],
				MaxVersion: "999",
				MinVersion: "0.0",
				component:  "python",
			},
		}

	default:
		return nil
	}

	// Deal with '@<user>/<package-name>' in NPM
	if strings.Contains(cpe[0].Name, "/") {
		nameArray := strings.Split(cpe[0].Name, "/")
		cpe[0].Name = nameArray[len(nameArray)-1]
	}

	vulnes.cpe = cpe
	vulnes.desc = fmt.Sprintf("Package '%s' is detected as malware, reference: https://www.oscs1024.com/hd/%s.",
		cpe[0].Name, vulnes.cveID)

	if vulnes != nil {
		err := c.update(vulnes)
		if err != nil {
			return err
		}
	}

	return nil
}
