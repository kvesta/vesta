LDFLAGS := -ldflags '-s -w'
TAGS := -tags netgo
LDFLAGS_STATIC := -ldflags '-w -s -extldflags "-static"'

IMAGE_TAG := latest
APP := kvesta/vesta

.PHONY: build
build:
	go build $(LDFLAGS) ./cmd/vesta

.PHONY: build.unix
build.unix:
	go build $(TAGS) $(LDFLAGS_STATIC) ./cmd/vesta

.PHONY: clean
clean:
	rm vesta

.PHONY: build.docker
build.docker:
	docker build -t $(APP):$(IMAGE_TAG) .

.PHONY: run.docker
run.docker:
	docker run --rm -ti --name vesta --network host -v `pwd`:/tool/output/ -v /var/run/docker.sock:/var/run/docker.sock ${APP}:${IMAGE_TAG} analyze docker