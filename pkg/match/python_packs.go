package match

import (
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
		"matplotlib", "pytest"}

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
func PyMalwareScan(filename string) string {
	f, err := os.Open(filename)
	if err != nil {
		return ""
	}

	defer f.Close()

	data, err := ioutil.ReadAll(f)
	if err != nil {
		return ""
	}

	if url := pyCheckLink(string(data)); url != "" {
		return url
	}

	return ""
}

func pyCheckLink(data string) string {

	httpRegex := []*regexp.Regexp{
		regexp.MustCompile(`(http[s]?:\/\/bit\.ly.*)$`),
		regexp.MustCompile(`(http[s]?:\/\/.*\.(link|xyz|tk|ml|ga|cf|gq|pw|top|club|mw|bd|ke|am|sbs|date|quest|cd|bid|cd|ws|icu|cam|uno|email|stream))$`),
		regexp.MustCompile(`(http[s]?:\/\/.*\.(link|xyz|tk|ml|ga|cf|gq|pw|top|club|mw|bd|ke|am|sbs|date|quest|cd|bid|cd|ws|icu|cam|uno|email|stream)\/)`),
	}

	urlCheck := func(match [][]string) string {
		for _, u := range match {
			for _, reg := range httpRegex {
				httpMatch := reg.FindStringSubmatch(u[1])
				if len(httpMatch) > 0 {
					return httpMatch[1]
				}
			}
		}
		return ""
	}

	urlDoubleMatch := pyDoubleQuoteRex.FindAllStringSubmatch(data, -1)
	urlSingleMatch := pySingleQuoteRex.FindAllStringSubmatch(data, -1)

	if url := urlCheck(urlDoubleMatch); url != "" {
		return url
	}

	if url := urlCheck(urlSingleMatch); url != "" {
		return url
	}

	return ""
}
