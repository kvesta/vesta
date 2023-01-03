package packages

import (
	"context"
	"log"
)

var (
	rpmId = []string{"centos", "rhel", "ol"}
)

func (s *Packages) GetApp(ctx context.Context) error {
	m := s.Mani
	s.Packs = []*Package{}
	for _, r := range rpmId {
		if s.OsRelease.OID == r {
			err = s.getRpmPacks(ctx)
			if err != nil {
				log.Printf("Get rpm packages failed: %v", err)
				return err
			}
			return nil
		}
	}

	rd, err := m.File("var/lib/dpkg/status")
	if err != nil {
		log.Printf("Dpkg get failed, error: %v", err)
	}
	dpkg := rd.String()
	if dpkg != "" {
		err = s.getAptPacks(ctx, dpkg)
	}
	rd, err = m.File("lib/apk/db/installed")
	if err != nil {
		log.Printf("Apk get failed, error: %v", err)
	}
	apk := rd.String()
	if apk != "" {
		err = s.getAptPacks(ctx, apk)
	}

	rd, err = m.File("var/log/pacman.log")
	if err != nil {
		log.Printf("Pacman get failed, error: %v", err)
	}
	pacman := rd.String()
	if pacman != "" {
		err = s.getArchPacks(ctx, pacman)
	}

	err = s.getSitePacks(ctx)
	err = s.Traverse(ctx)

	return err
}
