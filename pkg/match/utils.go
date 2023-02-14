package match

import (
	"strings"

	"github.com/sergi/go-diff/diffmatchpatch"
)

type Suspicion struct {
	Types      Operation
	OriginPack string
}

type Operation int8

const (
	// Unknown item represents package is not detected.
	Unknown Operation = 0
	// Confusion item represents package is suspect a malicious package.
	Confusion Operation = 1
	// Malware item represents package is discovered as malicious package.
	Malware Operation = 2
)

func compare(pack1, pack2 string) float64 {
	dmp := diffmatchpatch.New()
	diffs := dmp.DiffMain(pack1, pack2, false)
	matches := 0
	for _, diff := range diffs {
		if diff.Type == 0 {
			matches += len(diff.Text)
		}
	}

	sums := len(pack1) + len(pack2)
	if sums > 0 {
		return 2.0 * float64(matches) / float64(sums)
	}

	return 1.0
}

func confusionCheck(pack string, datas []string) string {
	for _, d := range datas {
		d = strings.ToLower(d)
		ratio := compare(pack, d)
		d = strings.ToLower(d)
		if ratio < 0.99 && ratio > 0.70 {
			return d
		}
	}
	return ""
}
