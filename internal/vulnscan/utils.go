package vulnscan

import (
	"os"
	"sort"
	"strings"

	"github.com/kvesta/vesta/config"
)

func sortSeverity(vulnComponents []*vulnComponent) {
	sort.Slice(vulnComponents, func(i, j int) bool {
		return config.SeverityMap[strings.ToLower(vulnComponents[i].Level)] > config.SeverityMap[strings.ToLower(vulnComponents[j].Level)]
	})
}

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
