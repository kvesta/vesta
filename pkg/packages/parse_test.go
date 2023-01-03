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
	defer f.Close()

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
			got, err := getGOPacks(tt.args.r)

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

func TestParseJava(t *testing.T) {
	type args struct {
		r io.ReaderAt
	}

	f, _ := os.Open("testdata/test.jar")
	defer f.Close()

	fi, _ := f.Stat()

	javaResult := &JAVA{
		Name: "Winstone",
		Jars: []*Jar{
			{
				Name:    "winstone",
				Version: "6.6",
			},
			{
				Name:    "slf4j-api",
				Version: "2.0.3",
			},
			{
				Name:    "slf4j-jdk14",
				Version: "2.0.3",
			},
		},
	}

	tests := []struct {
		name    string
		args    args
		want    *JAVA
		wantErr bool
	}{
		{
			name: "parseJavaTest",
			args: args{r: f},
			want: javaResult,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getJavaPacks(tt.args.r, fi.Size())

			if (err != nil) != tt.wantErr {
				t.Errorf("parseJava() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseJava() got = %v, want %v", got, tt.want)
			}
		})
	}
}
