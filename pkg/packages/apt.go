package packages

import (
	"context"
	"strings"
)

// getAptPacks get apt and dpkg packages
func (s *Packages) getAptPacks(ctx context.Context, dpkg string) error {
	packs := strings.Split(dpkg, "\n\n")
	for _, pe := range packs {
		if len(pe) < 1 {
			continue
		}
		p := &Package{}
		peLine := strings.Split(pe, "\n")
		for _, l := range peLine {
			index := strings.Index(l, ":")
			if index > -1 {
				values := strings.Split(l, ":")
				values[1] = strings.Replace(values[1], " ", "", -1)
				switch values[0] {
				// For ubuntu/debian
				case "Package":
					p.Name = values[1]
				case "Version":
					if len(values) > 2 {
						values[2] = strings.Replace(values[2], " ", "", -1)
						p.Version = values[2]
					} else {
						p.Version = values[1]
					}

				case "Architecture":
					p.Architecture = values[1]

				// For alpine linux
				case "P":
					p.Name = values[1]
				case "V":
					p.Version = values[1]

				default:
					// ignore
				}
			}
		}
		s.Packs = append(s.Packs, p)
	}
	return nil
}
