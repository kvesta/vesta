package match

import "strings"

var (
	npms = []string{"pug", "axios", "typescript", "mongodb", "lodash", "Mongoose", "redux",
		"jest", "qs", "rxjs", "fs-extra", "ua-parser-js", "koa", "express", "d3", "express", "http-proxy",
		"Fastify", "socket.io", "dotenv", "async", "mssql", "cross-env", "redis", "nedb", "fusion"}
)

func NpmMatch(pack string) Suspicion {
	t := Suspicion{
		Types: Unknown,
	}

	// filter the origin packages
	for _, npm := range npms {
		if pack == strings.ToLower(npm) {
			return t
		}
	}

	if p := confusionCheck(pack, npms); p != "" {
		t.Types = Confusion
		t.OriginPack = p
	}

	return t
}
