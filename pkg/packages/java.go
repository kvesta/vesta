package packages

import (
	"archive/zip"
	"errors"
	"io"
	"io/ioutil"
	"path/filepath"
	"regexp"
	"strings"
)

type JAVA struct {
	Name string `json:"name"`
	Path string `json:"path"`
	Jars []*Jar `json:"jars"`
}

type Jar struct {
	Name    string
	Version string
}

var (
	versionReg  = regexp.MustCompile(`version=(.*)`)
	artifactReg = regexp.MustCompile(`artifactId=(.*)`)
	NameRegs    = []*regexp.Regexp{
		regexp.MustCompile(`Implementation-Title: (.*)`),
		regexp.MustCompile(`Start-Class: (.*)`),
		regexp.MustCompile(`Specification-Title: (.*)`),
	}

	// Reference: https://github.com/aquasecurity/go-dep-parser/blob/main/pkg/java/jar/parse.go#L24
	jarRegEx   = regexp.MustCompile(`^([a-zA-Z0-9\._-]*[^-*])-(\d\S*(?:-SNAPSHOT)?).jar$`)
	jarNameMap = map[string]string{
		"log4j-core": "log4j",
	}
)

func getJavaPacks(rt io.ReaderAt, size int64) (*JAVA, error) {
	java := &JAVA{}
	jars := []*Jar{}

	jar, err := zip.NewReader(rt, size)
	if err != nil {
		return java, err
	}

	for _, f := range jar.File {
		switch {
		case strings.HasSuffix(f.Name, "pom.properties"):
			property, err := parseProperties(f)
			if err != nil {
				continue
			}
			jars = append(jars, property)

		case strings.HasSuffix(f.Name, "MANIFEST.MF"):
			java.Name = strings.TrimSpace(parseManifest(f))

		case strings.HasSuffix(f.Name, ".jar"):
			lib, err := parseLib(f.Name)
			if err != nil {
				continue
			}
			jars = append(jars, lib)

		default:
			// ignore
		}
	}

	java.Jars = jars

	return java, nil
}

func parseProperties(file *zip.File) (*Jar, error) {
	jar := &Jar{}

	jr, err := file.Open()
	if err != nil {
		return jar, err
	}

	defer jr.Close()

	d, _ := ioutil.ReadAll(jr)
	data := string(d)

	name := artifactReg.FindStringSubmatch(data)
	if len(name) > 1 {
		jar.Name = name[1]
	}

	jarVersion := versionReg.FindStringSubmatch(data)
	if len(jarVersion) > 1 {
		jar.Version = jarVersion[1]
	} else {
		err = errors.New("no version find")
		return jar, err
	}

	return jar, nil
}

func parseManifest(file *zip.File) string {

	mani, err := file.Open()
	if err != nil {
		return ""
	}

	defer mani.Close()
	d, _ := ioutil.ReadAll(mani)
	data := string(d)

	for _, reg := range NameRegs {
		title := reg.FindStringSubmatch(data)
		if len(title) > 1 {
			return title[1]
		}
	}

	return ""
}

func parseLib(jarName string) (*Jar, error) {
	jar := &Jar{}

	jarVersion := filepath.Base(jarName)
	jarMath := jarRegEx.FindStringSubmatch(jarVersion)

	if len(jarMath) > 2 {
		jar.Version = jarMath[2]
	} else {
		err := errors.New("not a jar library")
		return jar, err
	}

	jar.Name = jarMath[1]
	for k, v := range jarNameMap {
		if jar.Name == k {
			jar.Name = v
			break
		}
	}

	return jar, nil
}
