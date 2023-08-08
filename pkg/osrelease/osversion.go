package osrelease

import "time"

type OsVersion struct {
	NAME       string `json:"name"`
	OID        string `json:"oid"`
	VERSION    string `json:"version"`
	VERSION_ID string `json:"version___id"`
}

type KernelVersion struct {
	Version   string
	BuiltDate time.Time
}
