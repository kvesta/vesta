package analyzer

import (
	"sort"

	"github.com/kvesta/vesta/config"
)

func sortSeverity(threats []*threat) {
	sort.Slice(threats, func(i, j int) bool {
		return config.SeverityMap[threats[i].Severity] > config.SeverityMap[threats[j].Severity]
	})
}
