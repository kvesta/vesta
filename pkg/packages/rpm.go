package packages

import (
	"context"
	"path/filepath"

	rpmdb "github.com/knqyf263/go-rpmdb/pkg"
)

func (s *Packages) getRpmPacks(ctx context.Context) error {

	dbFiles := []string{
		"var/lib/rpm/Packages",
		"var/lib/rpm/Packages.db",
		"var/lib/rpm/rpmdb.sqlite",
	}

	for _, dbPath := range dbFiles {
		rpmPath := filepath.Join(s.Mani.Localpath, dbPath)

		db, err := rpmdb.Open(rpmPath)
		if err != nil {
			continue
		}
		defer db.Close()

		pkgList, err := db.ListPackages()
		if err != nil {
			continue
		}

		for _, pkg := range pkgList {
			p := &Package{
				Name:         pkg.Name,
				Version:      pkg.Version,
				Architecture: pkg.Arch,
			}

			s.Packs = append(s.Packs, p)
		}
	}

	return nil
}
