package layer

type Manifest struct {
	Name      string   `json:"name"`
	Hash      string   `json:"hash"`
	Layers    []*Layer `json:"layers"`
	Localpath string   `json:"localpath"`
}
