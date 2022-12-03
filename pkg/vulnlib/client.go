package vulnlib

import (
	"database/sql"
	"net/http"
)

type Client struct {
	Cli *http.Client
	DB  *sql.DB

	Store string
}

type DBRow struct {
	Id          int
	Hash        string
	VulnName    string
	MaxVersion  string
	MinVersion  string
	Description string
	Level       string
	CVEID       string
	Source      string
	PublishDate string
	Component   string
	Score       float64
}
