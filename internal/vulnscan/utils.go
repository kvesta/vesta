package vulnscan

import (
	"sort"
	"strings"

	"github.com/kvesta/vesta/config"
)

func sortSeverity(vulnComponents []*vulnComponent) {
	sort.Slice(vulnComponents, func(i, j int) bool {
		return config.SeverityMap[strings.ToLower(vulnComponents[i].Level)] > config.SeverityMap[strings.ToLower(vulnComponents[j].Level)]
	})
}
