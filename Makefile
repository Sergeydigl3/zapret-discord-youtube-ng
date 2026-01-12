.PHONY: proto build clean install-tools daemon cli

# protoc version requirement: 3.x or higher
# Install protoc from: https://github.com/protocolbuffers/protobuf/releases

# Install required protoc plugins
install-tools:
	@echo "Installing protoc plugins..."
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install github.com/twitchtv/twirp/protoc-gen-twirp@latest

# Generate protobuf and twirp code
proto:
	@echo "Generating protobuf and twirp code..."
	@PATH="$$HOME/bin:$$HOME/go/bin:$$PATH" protoc --proto_path=. \
		--go_out=. \
		--go_opt=paths=source_relative \
		--twirp_out=. \
		--twirp_opt=paths=source_relative \
		./rpc/daemon/service.proto

# Build daemon
daemon:
	@echo "Building zapret-daemon..."
	@mkdir -p out/bin
	go build -o out/bin/zapret-daemon ./cmd/zapret-daemon

# Build CLI
cli:
	@echo "Building zapret-ng CLI..."
	@mkdir -p out/bin
	go build -o out/bin/zapret-ng ./cmd/zapret

# Build both
build: proto daemon cli

# Clean generated files and binaries
clean:
	@echo "Cleaning..."
	rm -f rpc/daemon/*.pb.go
	rm -f rpc/daemon/*.twirp.go
	rm -rf out/

# Run daemon
run-daemon:
	@echo "Running daemon..."
	go run ./cmd/zapret-daemon serve

# Development: regenerate proto and rebuild
dev: proto build
