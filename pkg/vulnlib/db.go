package vulnlib

import (
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

func (cli *Client) Init() error {

	// Re-get homedir here
	dir, err := getHomeDir()
	if err != nil {
		log.Printf("failed to get home dir, error: %v", err)
		return err
	}

	var homedir string
	if runtime.GOOS == "windows" {
		homedir = filepath.Join(dir, "vestadata")
	} else {
		homedir = filepath.Join(dir, ".vesta")
	}

	if !exists(homedir) {
		err = mkFolder(homedir)

		if err != nil {
			log.Printf("failed to create folder, error: %v", err)
			return err
		}
	}

	dbPath := filepath.Join(homedir, "vesta.db")

	var db *sql.DB
	if !exists(dbPath) {
		file, err := os.Create(dbPath)
		if err != nil {
			return err
		}
		file.Close()
		db, _ = sql.Open("sqlite3", dbPath)
		vulTable := `CREATE TABLE vulns (
			"ID" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
			"Hash" TEXT UNIQUE,
			"VulnName" TEXT,
			"MaxVersion" TEXT,
			"MinVersion" TEXT,
			"Description" TEXT,
			"Level" TEXT,
			"CVEID" TEXT,
			"PublishDate" TEXT,
			"Component" TEXT,
			"Score" REAL,
			"Source" TEXT);`
		query, err := db.Prepare(vulTable)
		if err != nil {
			return err
		}
		query.Exec()
	} else {
		db, _ = sql.Open("sqlite3", dbPath)
	}

	cli.DB = db
	return nil
}

func (cli *Client) update(v *vuln) error {

	for _, cpe := range v.cpe {
		hash := md5.Sum([]byte(fmt.Sprintf("%s%s%s%s", cpe.Name, cpe.MaxVersion, cpe.MinVersion, v.cveID)))
		sqlRow := `INSERT INTO vulns 
					  ("Hash", "VulnName", "MaxVersion", "MinVersion", "Description", "Level", "CVEID", "PublishDate", "Component", "Score", "Source") 
                       VALUES
                      (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

		_, err := cli.DB.Exec(sqlRow, hex.EncodeToString(hash[:]), cpe.Name,
			cpe.MaxVersion, cpe.MinVersion, v.desc,
			v.level, v.cveID, v.publishDate,
			cpe.component, v.score, v.source)

		if err != nil {
			if strings.Contains(err.Error(), "vulns.Hash") {
				continue
			}
			return err
		}
	}

	return nil
}

func (cli *Client) QueryVulnByName(name string) ([]*DBRow, error) {

	dbRows := []*DBRow{}

	sqlRow := `SELECT * FROM vulns WHERE vulnname = ?`
	rows, err := cli.DB.Query(sqlRow, name)

	if err != nil {
		return dbRows, err
	}

	defer rows.Close()

	for rows.Next() {
		r := &DBRow{}
		err = rows.Scan(&r.Id, &r.Hash, &r.VulnName,
			&r.MaxVersion, &r.MinVersion, &r.Description,
			&r.Level, &r.CVEID, &r.PublishDate,
			&r.Component, &r.Score, &r.Source)

		if err != nil || r.MaxVersion == "*" {
			continue
		}

		dbRows = append(dbRows, r)
	}

	if err = rows.Err(); err != nil {
		return dbRows, err
	}

	return dbRows, nil
}

func (cli *Client) QueryVulnByCVEID(cveid string) ([]*DBRow, error) {

	dbRows := []*DBRow{}

	sqlRow := `SELECT * FROM vulns WHERE cveid = ?`
	rows, err := cli.DB.Query(sqlRow, cveid)

	if err != nil {
		return dbRows, err
	}

	defer rows.Close()

	for rows.Next() {
		r := &DBRow{}
		err = rows.Scan(&r.Id, &r.Hash, &r.VulnName,
			&r.MaxVersion, &r.MinVersion, &r.Description,
			&r.Level, &r.CVEID, &r.PublishDate,
			&r.Component, &r.Score, &r.Source)

		if err != nil || r.MaxVersion == "*" {
			continue
		}

		dbRows = append(dbRows, r)
	}

	if err = rows.Err(); err != nil {
		return dbRows, err
	}

	return dbRows, nil
}
