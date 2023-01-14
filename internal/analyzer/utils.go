package analyzer

import (
	"fmt"
	"regexp"
	"sort"

	"github.com/kvesta/vesta/config"
)

var (
	passKey = []*regexp.Regexp{
		regexp.MustCompile(`(?i)password`),
		regexp.MustCompile(`(?i)pwd`),
		regexp.MustCompile(`(?i)token`),
	}
)

func checkWeakPassword(pass string) string {
	countCase := 0

	// Particularly checking the keyword
	keyWords := []string{"password", "admin", "qwerty", "1q2w3e", "123456"}
	for _, keyword := range keyWords {
		replmatch := regexp.MustCompile(fmt.Sprintf(`(?i)%s`, keyword))
		pass = replmatch.ReplaceAllString(pass, "")
	}

	length := len(pass)

	lowerCase := regexp.MustCompile(`[a-z]`)
	lowerMatch := lowerCase.FindStringSubmatch(pass)
	if len(lowerMatch) > 0 {
		countCase += 1
	}

	upperCase := regexp.MustCompile(`[A-Z]`)
	upperMatch := upperCase.FindStringSubmatch(pass)
	if len(upperMatch) > 0 {
		countCase += 1
	}

	numberCase := regexp.MustCompile(`[\d]`)
	numberMatch := numberCase.FindStringSubmatch(pass)
	if len(numberMatch) > 0 {
		countCase += 1
	}

	characterCase := regexp.MustCompile(`[^\w]`)
	characterMatch := characterCase.FindStringSubmatch(pass)
	if len(characterMatch) > 0 {
		countCase += 1
	}

	if length <= 6 {
		switch countCase {
		case 4:
			return "Medium"
		default:
			return "Weak"
		}

	} else if length > 6 && length <= 10 {
		switch countCase {
		case 4, 3:
			return "Strong"
		case 2:
			return "Medium"
		case 1, 0:
			return "Weak"

		}
	} else {
		if countCase < 2 {
			return "Medium"
		}
	}

	return "Strong"
}

func sortSeverity(threats []*threat) {
	sort.Slice(threats, func(i, j int) bool {
		return config.SeverityMap[threats[i].Severity] > config.SeverityMap[threats[j].Severity]
	})
}
