GO_BUILD_FLAGS=-a -ldflags='-s -w' -trimpath # -linkmode external -extldflags=-static
GO_MAIN_PACKAGE="./cmd/server"
DIST_FOLDER="dist"

.PHONY: clean tidy download build

default: build

tidy:
	@go mod tidy

download: tidy
	@echo Download go.mod dependencies
	@go mod download

dist/smolmailer_linux_amd64: download
	@echo Building linux amd64 binary
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build $(GO_BUILD_FLAGS) -o $@ $(GO_MAIN_PACKAGE)

dist/smolmailer_linux_arm64: download
	@echo Building linux arm64 binary
	CGO_ENABLED=1 GOOS=linux GOARCH=arm64 go build $(GO_BUILD_FLAGS) -o $@ $(GO_MAIN_PACKAGE)

dist/smolmailer_native: download
	CGO_ENABLED=1 go build $(GO_BUILD_FLAGS) -o $@ $(GO_MAIN_PACKAGE)

build: dist/smolmailer_linux_arm64 dist/smolmailer_linux_amd64

clean:
	@rm -rf $(DIST_FOLDER)/*

# Shouldn't be necessary any more
# install-tools: download
#   @echo Installing tools from tools.go
#   @cat tools.go | grep _ | awk -F'"' '{print $$2}' | xargs -tI % go install %
