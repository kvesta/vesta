package match

import (
	"strings"
)

var (
	pypis = []string{"requests", "Django", "Flask", "datadog", "numpy", "Pillow", "PyYAML", "PySocks",
		"Scrapy", "scipy", "Twisted", "torch", "torchvision", "pandas", "pastas", "algoliasearch", "tornado",
		"pypcap", "semidbm", "signalfx", "cassandra-driver", "ShopifyAPI", "zoomeye", "osc",
		"distributed", "virtualenv", "selenium", "bs4", "beautifulsoup4", "lxml", "pylint"}

	maliciousPypis = map[string]string{
		"smi":          "pysmi",
		"smb":          "pysmb",
		"opencv":       "opencv-python",
		"python-mysql": "PyMySQL",
		"python-ftp":   "pyftpdlib",
		"ascii2text":   "art",
		"zlibsrc":      "zlib",
		"browserdiv":   "pybrowsers",
	}
)

func PyMatch(pack string) Suspicion {
	t := Suspicion{
		Types: Unknown,
	}
	pack = strings.ToLower(pack)
	if p := malwareCheck(pack); p != "" {
		t.Types = Malware
		t.OriginPack = p
		return t
	}

	if p := confusionCheck(pack); p != "" {
		t.Types = Confusion
		t.OriginPack = p
	}

	return t
}

func confusionCheck(pack string) string {
	for _, pip := range pypis {
		pip = strings.ToLower(pip)
		ratio := compare(pack, pip)
		pip = strings.ToLower(pip)
		if ratio < 0.99 && ratio > 0.70 {
			return pip
		}
	}
	return ""
}

func malwareCheck(pack string) string {
	for mal, ori := range maliciousPypis {
		if pack == mal {
			return ori
		}
	}
	return ""
}
