package vulnlib

import (
	"context"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/kvesta/vesta/config"
)

// Fetch get cvss data from Internet
func Fetch(ctx context.Context) error {
	log.Printf(config.Green("Begin updating vulnerability database"))

	tr := &http.Transport{
		IdleConnTimeout:    60 * time.Second,
		DisableCompression: true,
	}

	cli := Client{
		Cli: &http.Client{
			Transport: tr,
		},
	}

	dir, err := getHomeDir()
	if err != nil {
		log.Printf("failed to get home dir, error: %v", err)
		return err
	}

	var store string
	if runtime.GOOS == "windows" {
		store = filepath.Join(dir, "vestadata")

	} else {
		store = filepath.Join(dir, ".vesta")
	}

	if ctx.Value("reset") != nil && ctx.Value("reset").(bool) {
		dataFile := filepath.Join(store, "date.txt")
		dbFile := filepath.Join(store, "vesta.db")

		_ = os.Remove(dataFile)
		_ = os.Remove(dbFile)
	}

	if !exists(store) {
		err = mkFolder(store)

		if err != nil {
			log.Printf("failed to create folder, error: %v", err)
			return err
		}
	}

	if !checkExpired(store) {
		log.Printf("Vulnerability Database is already initialized")
		return nil
	} else {
		log.Printf("Vulnerability Data expired, updating database")
	}

	cli.Store = store
	err = cli.Init()
	if err != nil {
		log.Printf("failed to init database")
		return err
	}

	defer cli.DB.Close()

	// Get cvss data and store to database
	err = cli.GetCvss(ctx)
	if err != nil {
		log.Printf("failed to get cvss data, error: %v", err)
	}

	// Get OSCS data for poised package
	err = cli.GetOSCS(ctx)
	if err != nil {
		log.Printf("failed to get oscs data, error: %v", err)
	}

	// Write log
	err = writeLog(store)
	if err != nil {
		log.Printf("failed to write date log, error: %v", err)
	}

	return nil
}

func getHomeDir() (string, error) {
	if runtime.GOOS == "windows" {
		dir, err := os.Getwd()
		if err != nil {
			return "", nil
		}
		return dir, nil
	}

	dir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return dir, nil
}

func exists(path string) bool {
	_, err := os.Stat(path)
	if err != nil {
		if os.IsExist(err) {
			return true
		}

		return false
	}
	return true
}

func mkFolder(path string) error {
	if !exists(path) {
		err := os.MkdirAll(path, os.FileMode(0755))
		if err != nil {
			return err
		}
	}
	return nil
}

func checkExpired(path string) bool {

	filename := filepath.Join(path, "date.txt")
	var dateFile *os.File
	var err error

	if !exists(filename) {
		return true

	} else {
		dateFile, err = os.Open(filename)
		if err != nil {
			log.Printf("failed to open date: %v", err)
			return true
		}
	}

	defer dateFile.Close()

	value, err := ioutil.ReadAll(dateFile)
	if err != nil {
		return true
	}

	today := time.Now()

	if len(value) < 1 {

		return true
	}

	logDate, err := time.Parse("02/01/2006", string(value))

	// Check whether a time format
	if err != nil {
		log.Printf("Date format error, expired")
		return true
	}

	if expire := today.After(logDate.AddDate(0, 0, 1)); expire {
		return true
	}

	return false
}

func writeLog(path string) error {

	filename := filepath.Join(path, "date.txt")

	if !exists(filename) {
		f, err := os.Create(filename)
		if err != nil {
			log.Printf("failed to create log")
			return err
		}
		f.Close()
	}

	today := time.Now()

	dateFile, err := os.OpenFile(filename, os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("failed to open log")
		return err
	}

	defer dateFile.Close()

	_, err = dateFile.WriteString(today.Format("02/01/2006"))
	if err != nil {
		return err
	}
	return nil
}
