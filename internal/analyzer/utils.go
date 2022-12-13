package analyzer

import "sort"

var SeverityMap = map[string]int{
	"critical": 5,
	"high":     4,
	"medium":   3,
	"low":      2,
	"tips":     1,
}

func sortSeverity(threats []*threat) {
	sort.Slice(threats, func(i, j int) bool {
		return SeverityMap[threats[i].Severity] > SeverityMap[threats[j].Severity]
	})
}
