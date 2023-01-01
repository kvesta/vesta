package packages

import (
	"io"
	"os"
	"reflect"
	"testing"
)

func TestParseGo(t *testing.T) {
	type args struct {
		r io.ReaderAt
	}
	f, _ := os.Open("testdata/gobintest")

	goResult := &GOBIN{
		Name: "gobinary",
		Deps: []*MOD{
			{
				Name:    "go-querystring",
				Path:    "github.com/google/go-querystring",
				Version: "v1.1.0",
			},
		},
	}

	tests := []struct {
		name    string
		args    args
		want    *GOBIN
		wantErr bool
	}{
		{
			name: "parseGoTest",
			args: args{r: f},
			want: goResult,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseGo(tt.args.r)

			if (err != nil) != tt.wantErr {
				t.Errorf("parseGo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseGo() got = %v, want %v", got, tt.want)
			}
		})
	}
}
