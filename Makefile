.PHONY: build install clean test fmt lint release-dry-run

BINARY := claw-wrap
BUILD_DIR := ./build
INSTALL_DIR := /usr/local/bin

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -s -w -X main.version=$(VERSION)

build:
	go build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY) ./cmd/claw-wrap

install: build
	sudo cp $(BUILD_DIR)/$(BINARY) $(INSTALL_DIR)/$(BINARY)
	sudo chmod 755 $(INSTALL_DIR)/$(BINARY)
	@echo "Installed $(BINARY) to $(INSTALL_DIR)"

install-symlinks: install
	sudo $(INSTALL_DIR)/$(BINARY) install

clean:
	rm -rf $(BUILD_DIR)
	go clean

test:
	go test -v ./...

fmt:
	go fmt ./...

lint:
	go vet ./...

# Development helpers
dev: fmt lint build

run-daemon: build
	$(BUILD_DIR)/$(BINARY) daemon

release-dry-run:
	goreleaser release --snapshot --clean

# Remove old standalone claw-wrap.go if it exists
clean-old:
	rm -f claw-wrap.go
