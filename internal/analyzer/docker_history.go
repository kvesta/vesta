package analyzer

import (
	"fmt"
	"log"
	"regexp"
	"strings"

	imagev1 "github.com/docker/docker/api/types/image"
	_config "github.com/kvesta/vesta/config"
	_image "github.com/kvesta/vesta/pkg/inspector"
)

func CheckHistories(images []*_image.ImageInfo) (bool, []*threat) {
	log.Printf(_config.Yellow("Begin image histories analyzing"))

	var vuln = false
	tlist := []*threat{}

	echoReg := regexp.MustCompile(`echo ["|'](.*?)["|']`)

	for _, img := range images {
		env := getEnv(img.History)

		// Check the sensitive environment
		if ok, tl := checkEnv(env); ok {

			for _, th := range tl {
				th.Value = fmt.Sprintf("Image name: %s | "+
					"Image ID: %s", img.Summary.RepoTags[0],
					strings.TrimPrefix(img.Summary.ID, "sha256:")[:12])
				tlist = append(tlist, th)
			}

			vuln = true
		}

		for _, layer := range img.History {
			pruneLayerAfter1 := strings.TrimPrefix(layer.CreatedBy, "/bin/sh -c ")
			pruneLayerAfter2 := strings.TrimPrefix(pruneLayerAfter1, "#(nop)")
			pruneLayer := strings.TrimSpace(pruneLayerAfter2)

			link := strings.Split(pruneLayer, " ")[0]
			switch link {
			case "CMD", "ADD", "ARG", "LABEL", "WORKDIR", "COPY", "EXPOSE", "ENTRYPOINT", "USER":
				continue
			case "ENV":
				values := strings.Split(pruneLayer, "=")
				detect := maliciousContentCheck(values[1])
				switch detect.Types {
				case Executable:
					th := &threat{
						Param: "Image History",
						Value: fmt.Sprintf("Image name: %s | "+
							"Image ID: %s", img.Summary.RepoTags[0],
							strings.TrimPrefix(img.Summary.ID, "sha256:")[:12]),
						Describe: fmt.Sprintf("Executable value found in ENV: '%s' "+
							"with the plain text '%s'.", strings.TrimPrefix(values[0], "ENV "), detect.Plain),
						Severity: "high",
					}

					tlist = append(tlist, th)
					vuln = true

				case Confusion:
					th := &threat{
						Param: "Image History",
						Value: fmt.Sprintf("Image name: %s | "+
							"Image ID: %s", img.Summary.RepoTags[0],
							strings.TrimPrefix(img.Summary.ID, "sha256:")[:12]),
						Describe: fmt.Sprintf("Confusion value found in ENV: '%s' "+
							"with the plain text '%s'.", strings.TrimPrefix(values[0], "ENV "), detect.Plain),
						Severity: "high",
					}

					tlist = append(tlist, th)
					vuln = true
				default:
					// ignore
				}

				continue
			}

			commands := strings.Split(pruneLayer, "&&")
			for _, cmd := range commands {
				detectCmd := maliciousContentCheck(strings.TrimSpace(cmd))
				if detectCmd.Types > Unknown {
					th := &threat{
						Param: "Image History",
						Value: fmt.Sprintf("Image name: %s | "+
							"Image ID: %s", img.Summary.RepoTags[0],
							strings.TrimPrefix(img.Summary.ID, "sha256:")[:12]),
						Describe: fmt.Sprintf("Malicious cmd found in RUN: '%s' "+
							"with the plain text '%s'.", cmd, detectCmd.Plain),
						Severity: "high",
					}

					tlist = append(tlist, th)
					vuln = true

					continue
				}

				// Check the content of `echo` command
				echoMatch := echoReg.FindStringSubmatch(cmd)
				if len(echoMatch) > 1 {
					detectEcho := maliciousContentCheck(echoMatch[1])
					if detectEcho.Types > Unknown {
						th := &threat{
							Param: "Image History",
							Value: fmt.Sprintf("Image name: %s | "+
								"Image ID: %s", img.Summary.RepoTags[0],
								strings.TrimPrefix(img.Summary.ID, "sha256:")[:12]),
							Describe: fmt.Sprintf("Malicious value found in RUN: '%s' "+
								"with the plain text '%s'.", cmd, detectEcho.Plain),
							Severity: "high",
						}

						tlist = append(tlist, th)
						vuln = true

						continue
					}

					pass := echoPass(echoMatch[1], env)
					if len(pass) < 1 {
						continue
					}
					switch checkWeakPassword(pass) {
					case "Weak":
						th := &threat{
							Param: "Image History",
							Value: fmt.Sprintf("Image name: %s | "+
								"Image ID: %s", img.Summary.RepoTags[0],
								strings.TrimPrefix(img.Summary.ID, "sha256:")[:12]),
							Describe: fmt.Sprintf("Weak password found in command: '%s' "+
								"with the password '%s'.", cmd, pass),
							Severity: "high",
						}

						tlist = append(tlist, th)
						vuln = true

					case "Medium":
						th := &threat{
							Param: "Image History",
							Value: fmt.Sprintf("Image name: %s | "+
								"Image ID: %s", img.Summary.RepoTags[0],
								strings.TrimPrefix(img.Summary.ID, "sha256:")[:12]),
							Describe: fmt.Sprintf("Password need need to be reinforeced, found in command: '%s'.", cmd),
							Severity: "medium",
						}

						tlist = append(tlist, th)
						vuln = true
					}
				}

			}

		}
	}

	return vuln, tlist
}

func echoPass(cmd string, env map[string]string) string {

	var pass string
	match := false
	for _, p := range passKey {
		if p.MatchString(cmd) {
			match = true
			break
		}
	}

	if !match {
		return pass
	}

	prune := strings.TrimSpace(cmd)

	if len(strings.Split(prune, "=")) > 1 {
		pass = strings.Split(prune, "=")[1]
	} else if len(strings.Split(prune, ":")) > 1 {
		pass = strings.Split(prune, ":")[1]
	}

	pass = strings.TrimSpace(pass)

	// Get true value from format `${env}`
	envReg := regexp.MustCompile(`\${(.*)}`)
	envMatch := envReg.FindStringSubmatch(pass)
	if len(envMatch) > 1 {
		if value, ok := env[envMatch[1]]; ok {
			pass = value
		}
	}

	return pass
}

func getEnv(images []imagev1.HistoryResponseItem) map[string]string {
	env := map[string]string{}

	for _, layer := range images {
		pruneLayerAfter1 := strings.TrimPrefix(layer.CreatedBy, "/bin/sh -c ")
		pruneLayerAfter2 := strings.TrimPrefix(pruneLayerAfter1, "#(nop)")
		pruneLayer := strings.TrimSpace(pruneLayerAfter2)

		link := strings.Split(pruneLayer, " ")[0]
		if link != "ENV" {
			continue
		}
		envLayer := strings.TrimPrefix(pruneLayer, "ENV ")
		e := strings.Split(envLayer, "=")
		env[e[0]] = e[1]
	}

	return env
}

func checkEnv(env map[string]string) (bool, []*threat) {
	var vuln = false
	tlist := []*threat{}

	for key, value := range env {
		for _, p := range passKey {
			if p.MatchString(key) {

				th := &threat{
					Param: "Image History",
					Describe: fmt.Sprintf("Docker history has found the senstive environment"+
						" with key '%s' and value: %s.", key, value),
					Severity: "medium",
				}

				tlist = append(tlist, th)
				vuln = true

				break
			}
		}

	}

	return vuln, tlist
}
