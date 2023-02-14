package match

import (
	"strings"
)

var (
	pypis = []string{"requests", "Django", "Flask", "datadog", "numpy", "Pillow", "PyYAML", "PySocks",
		"Scrapy", "scipy", "scapy", "Twisted", "torch", "torchvision", "pandas", "pastas", "algoliasearch", "tornado",
		"pypcap", "semidbm", "signalfx", "cassandra-driver", "ShopifyAPI", "zoomeye", "osc", "PyPtt", "flake8",
		"distributed", "virtualenv", "selenium", "bs4", "beautifulsoup4", "lxml", "pylint", "pywin32", "web3", "pyebpf"}

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
	}
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
		t.Types = Malware
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
