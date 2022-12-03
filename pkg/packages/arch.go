package packages

import (
	"context"
	"regexp"
	"strings"
)

func (s *Packages) getArchPacks(ctx context.Context, pacman string) error {
	packs := strings.Split(pacman, "\n")
	for _, pe := range packs {
		if len(pe) < 1 {
			continue
		}
		index := strings.Index(pe, "[ALPM] installed")
		if index > -1 {
			p := &Package{}
			inform := regexp.MustCompile(`((\w+\-)?(\w+\-)?(\w+))?\s\((.*?)\)`)
			value := inform.FindStringSubmatch(pe)
			if len(value) > 0 {
				v := strings.Split(value[0], " ")
				p.Name = v[0]
				p.Version = value[len(value)-1]
			}
			s.Packs = append(s.Packs, p)
		}

	}
	return nil
}
