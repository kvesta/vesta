package match

import (
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strings"
)

var (
	pypis = []string{"requests", "Django", "Flask", "datadog", "numpy", "Pillow", "PyYAML", "PySocks",
		"Scrapy", "scipy", "scapy", "Twisted", "torch", "torchvision", "pandas", "pastas", "algoliasearch", "tornado",
		"pypcap", "semidbm", "signalfx", "cassandra-driver", "ShopifyAPI", "zoomeye", "osc", "PyPtt", "flake8", "opencv-python",
		"distributed", "virtualenv", "selenium", "bs4", "beautifulsoup4", "lxml", "pylint", "pywin32", "web3", "pyebpf",
		"matplotlib", "pytest", "paramiko", "PySMT", "claripy", "angr"}

	maliciousPypis = map[string]string{
		"smi":          "pysmi",
		"smb":          "pysmb",
		"opencv":       "opencv-python",
		"python-mysql": "PyMySQL",
		"python-ftp":   "pyftpdlib",
		"ascii2text":   "art",
		"zlibsrc":      "zlib",
		"browserdiv":   "pybrowsers",
		"pwn":          "pwntools",
		"pymocks":      "unittest.mock",
		"PyProto2":     "unknown",
		"free-net-vpn": "unknown",
		"ebpf":         "pyebpf",
		"yaml":         "PyYAML",
	}

	pyDoubleQuoteRex = regexp.MustCompile(`"(.*?)"`)
	pySingleQuoteRex = regexp.MustCompile(`'(.*?)'`)
)

func PyMatch(pack string) Suspicion {
	t := Suspicion{
		Types: Unknown,
	}
	pack = strings.ToLower(pack)

	// filter the origin packages
	for _, pypi := range pypis {
		if pack == strings.ToLower(pypi) {
			return t
		}
	}

	if p := malwareCheck(pack); p != "" {
		t.Types = Confusion
		t.OriginPack = p
		return t
	}

	if p := confusionCheck(pack, pypis); p != "" {
		t.Types = Confusion
		t.OriginPack = p
	}

	return t
}

func malwareCheck(pack string) string {
	for mal, ori := range maliciousPypis {
		if pack == mal {
			return ori
		}
	}
	return ""
}

// PyMalwareScan the malicious packages from pip
// reference: https://github.com/DataDog/guarddog
func PyMalwareScan(filename string) Suspicion {
	t := Suspicion{
		Types: Unknown,
	}

	f, err := os.Open(filename)
	if err != nil {
		return t
	}

	defer f.Close()

	data, err := ioutil.ReadAll(f)
	if err != nil {
		return t
	}

	d := []string{}

	doubleQuotesMatch := pyDoubleQuoteRex.FindAllStringSubmatch(string(data), -1)
	singleQuotesMatch := pySingleQuoteRex.FindAllStringSubmatch(string(data), -1)

	for _, q := range doubleQuotesMatch {
		d = append(d, q[1])
	}
	for _, q := range singleQuotesMatch {
		d = append(d, q[1])
	}

	if url := pyCheckLink(d); url != "" {
		t.Types = Malware
		t.OriginPack = fmt.Sprintf("suspcious url '%s' are detected.", url)

		return t
	}

	if command := pyCheckCommand(d, string(data)); command != "" {
		t.Types = Malware
		t.OriginPack = fmt.Sprintf(`malicious command "%s" are detected.`, command)

		return t
	}

	return t
}

func pyCheckLink(d []string) string {

	httpRegex := []*regexp.Regexp{
		regexp.MustCompile(`(http[s]?:\/\/bit\.ly.*)$`),
		regexp.MustCompile(`(http[s]?:\/\/.*\.(link|xyz|tk|ml|ga|cf|gq|pw|top|club|mw|bd|ke|am|sbs|date|quest|cd|bid|cd|ws|icu|cam|uno|email|stream))$`),
		regexp.MustCompile(`(http[s]?:\/\/.*\.(link|xyz|tk|ml|ga|cf|gq|pw|top|club|mw|bd|ke|am|sbs|date|quest|cd|bid|cd|ws|icu|cam|uno|email|stream)\/)`),
	}

	for _, l := range d {
		for _, reg := range httpRegex {
			httpMatch := reg.FindStringSubmatch(l)
			if len(httpMatch) > 0 {
				return httpMatch[1]
			}
		}
	}
	return ""

}

func pyCheckCommand(d []string, data string) string {
	execRegex := []*regexp.Regexp{
		regexp.MustCompile(`os.system\((.*)\)`),
		regexp.MustCompile(`exec\((.*)\)`),
		regexp.MustCompile(`os.popen\((.*)\)`),
		regexp.MustCompile(`eval\((.*)\)`),
		regexp.MustCompile(`subprocess.Popen\((.*)$,.*\)`),
		regexp.MustCompile(`os.execl\((.*)\)`),
		regexp.MustCompile(`os.execve\((.*)\)`),
		regexp.MustCompile(`os.spawnl\((.*)\)`),
		regexp.MustCompile(`globals\(\)['eval']\((.*)\)`),
	}

	for _, l := range d {
		// Plain test checking
		if strings.Contains(l, "powershell") || strings.Contains(l, "chmod +x") ||
			strings.Contains(l, "/dev/tcp/") ||
			(strings.Contains(l, "curl") || strings.Contains(l, "wget") && strings.Contains(l, "bash")) {
			return l
		}
	}

	for _, reg := range execRegex {
		regMatch := reg.FindStringSubmatch(data)
		if len(regMatch) < 2 {
			continue
		}

		if len(regMatch[1]) > 30 {
			return regMatch[0]
		}

	}

	return ""
}
