package analyzer

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/shirou/gopsutil/process"
	"gopkg.in/yaml.v3"
)

func (ks *KScanner) checkEnvoy() error {

	type envoyAdmin struct {
		Admin struct {
			Address struct {
				SocketAddress struct {
					Address   string `yaml:"address" json:"address"`
					PortValue string `yaml:"port_value" json:"port_value"`
				} `yaml:"socket_address" json:"socket_address"`
			} `yaml:"address" json:"address"`
		} `yaml:"admin" json:"admin"`
	}

	// Only supports Linux
	if runtime.GOOS != "linux" {
		return nil
	}

	var filename string
	var envoyConfig envoyAdmin

	// Check process or docker to find envoy
	processes, _ := process.Processes()
	for _, ps := range processes {
		cmds, _ := ps.CmdlineSlice()
		if len(cmds) < 1 {
			continue
		}

		if !strings.Contains(cmds[0], "envoy") {
			continue
		}

		cwd := fmt.Sprintf("/proc/%d/cwd/", ps.Pid)

		// Get the name of config file
		for i, p := range cmds {
			if p == "-c" {
				filename = cmds[i+1]
				break
			}
		}

		configFile := filepath.Join(cwd, filename)

		// Judge file type
		fileSplit := strings.Split(configFile, ".")
		fileType := fileSplit[len(fileSplit)-1]

		f, err := os.Open(configFile)
		if err != nil {
			continue
		}

		config, err := io.ReadAll(f)
		if err != nil {
			f.Close()
			continue
		}

		f.Close()

		switch fileType {
		case "yaml":
			err = yaml.Unmarshal(config, &envoyConfig)
			if err != nil {
				continue
			}

		case "json":
			err = json.Unmarshal(config, &envoyConfig)
			if err != nil {
				continue
			}

		default:
			continue

		}

		if envoyConfig != (envoyAdmin{}) {

			address := envoyConfig.Admin.Address.SocketAddress.Address
			port := envoyConfig.Admin.Address.SocketAddress.PortValue

			envoyCommand := strings.Join(cmds[1:], " ")
			if len(envoyCommand) > 80 {
				envoyCommand = "envoy " + envoyCommand[:80] + "..."
			}

			th := &threat{
				Param: "admin",
				Value: fmt.Sprintf("Pid:%d \nCommand:\n \"%s\"", ps.Pid, envoyCommand),
				Type:  "Envoy",
				Describe: fmt.Sprintf("Envoy admin is activated and exposed to '%s:%s', "+
					"which includes sensitive api and unauthorized.", address, port),
				Reference: "https://www.envoyproxy.io/docs/envoy/latest/operations/admin#administration-interface",
				Severity:  "medium",
			}

			if address == "0.0.0.0" {
				th.Severity = "high"
			}

			ks.VulnConfigures = append(ks.VulnConfigures, th)
		}

	}

	return nil
}

func (ks *KScanner) checkIstio() error {
	return nil
}

func (ks *KScanner) checkCilium() error {
	return nil
}
