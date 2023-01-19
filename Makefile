LDFLAGS := -ldflags '-s -w'

.PHONY: build
build:
	go build $(LDFLAGS) ./cmd/vesta

.PHONY: clean
clean:
	rm vesta
