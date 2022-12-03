package osrelease

type OsVersion struct {
	NAME       string `json:"name"`
	OID        string `json:"oid"`
	VERSION    string `json:"version"`
	VERSION_ID string `json:"version___id"`
}
