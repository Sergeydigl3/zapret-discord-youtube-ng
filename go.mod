module github.com/Sergeydigl3/zapret-discord-youtube-ng

go 1.25

toolchain go1.25.5

tool (
	github.com/twitchtv/twirp/protoc-gen-twirp
	google.golang.org/protobuf/cmd/protoc-gen-go
)

require (
	github.com/coreos/go-iptables v0.8.0
	github.com/fsnotify/fsnotify v1.9.0
	github.com/ilyakaznacheev/cleanenv v1.5.0
	github.com/spf13/cobra v1.10.2
	github.com/twitchtv/twirp v8.1.3+incompatible
	google.golang.org/protobuf v1.36.11
)

require (
	github.com/BurntSushi/toml v1.2.1 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/joho/godotenv v1.5.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	github.com/stretchr/testify v1.11.1 // indirect
	golang.org/x/sys v0.28.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	olympos.io/encoding/edn v0.0.0-20201019073823-d3554ca0b0a3 // indirect
)
