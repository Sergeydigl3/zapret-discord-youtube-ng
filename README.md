# zapret-daemon

Демон-сервис для управления zapret с интерфейсом командной строки. Использует Twirp RPC для коммуникации между клиентом и демоном.

## Возможности

- Демон-сервис с поддержкой Unix socket и сетевых соединений
- CLI клиент для управления демоном
- Структурированное логирование с помощью slog
- Конфигурация через YAML или переменные окружения
- RPC коммуникация через Twirp (совместимость с HTTP/1.1 и HTTP/2)

## Требования

- Go 1.21+
- protoc (Protocol Buffers compiler)

## Поддерживаемые платформы

### Пакеты (Linux)
- **Debian/Ubuntu**: amd64, arm64, armhf (ARMv7), i386
- **RHEL/CentOS/Fedora**: x86_64, aarch64, armhfp (ARMv7), i386
- **Alpine Linux**: x86_64, aarch64, armhf (ARMv7)
- **Arch Linux**: x86_64, aarch64, armv7h (ARMv7)

### Архивы (все ОС)
- **Linux**: amd64, arm64, armv7, i386
- **macOS**: x86_64, arm64 (Apple Silicon)
- **Windows**: x86_64, i386
- **FreeBSD**: x86_64, arm64
- **Android**: arm64, armv7

## Установка

### Установка последней версии (Linux)

Самый простой способ установить последнюю версию на Linux (работает с `curl` или `wget`):

**С использованием `curl`:**
```bash
curl -fsSL https://raw.githubusercontent.com/Sergeydigl3/zapret-discord-youtube-ng/refs/heads/master/install.sh | sudo sh
```

**С использованием `wget`:**
```bash
wget -qO- https://raw.githubusercontent.com/Sergeydigl3/zapret-discord-youtube-ng/refs/heads/master/install.sh | sudo sh
```

Или скачайте и запустите скрипт вручную:

```bash
# С curl
curl -fsSL https://raw.githubusercontent.com/Sergeydigl3/zapret-discord-youtube-ng/refs/heads/master/install.sh -o install.sh

# Или с wget
wget https://raw.githubusercontent.com/Sergeydigl3/zapret-discord-youtube-ng/refs/heads/master/install.sh

# Запуск (работает в любом sh, включая Alpine Linux)
sudo sh install.sh
```

Скрипт автоматически:
- Определит вашу систему (дистрибутив и архитектуру)
- Найдет доступный инструмент для загрузки (curl или wget)
- Скачает системный пакет (deb/rpm/apk/pkg.tar.zst)
- Установит пакет через системный пакетный менеджер
- Настроит сервис и конфигурацию

### Удаление

Для удаления используйте тот же скрипт с флагом `--uninstall`:

```bash
# С curl
curl -fsSL https://raw.githubusercontent.com/Sergeydigl3/zapret-discord-youtube-ng/refs/heads/master/install.sh | sudo sh -s -- --uninstall

# С wget
wget -qO- https://raw.githubusercontent.com/Sergeydigl3/zapret-discord-youtube-ng/refs/heads/master/install.sh | sudo sh -s -- --uninstall

# Или локально
sudo sh install.sh --uninstall
```

Скрипт удалит:
- Пакет через системный пакетный менеджер
- Конфигурационные файлы (/etc/zapret-ng)
- Runtime файлы (/run/zapret)
- Бинарники (/usr/bin/zapret-daemon, /usr/bin/zapret-ng)

### Установка на других платформах

Для macOS, Windows, FreeBSD и Android скачайте архив напрямую с [GitHub Releases](https://github.com/Sergeydigl3/zapret-discord-youtube-ng/releases).

### Сборка из исходников

#### Установка зависимостей

```bash
# Установить protoc (если еще не установлен)
# Linux:
mkdir -p ~/bin
cd /tmp
curl -LO https://github.com/protocolbuffers/protobuf/releases/download/v28.3/protoc-28.3-linux-x86_64.zip
unzip protoc-28.3-linux-x86_64.zip -d protoc-install
cp protoc-install/bin/protoc ~/bin/
rm -rf protoc-28.3-linux-x86_64.zip protoc-install

# Установить Go плагины для protoc
make install-tools
```

#### Сборка

```bash
# Сгенерировать protobuf код и собрать все бинарники
make build

# Или по отдельности:
make proto    # Генерация protobuf/twirp кода
make daemon   # Сборка демона
make cli      # Сборка CLI
```

Бинарники будут созданы в директории `out/bin/`:
- `out/bin/zapret-daemon` - демон-сервис
- `out/bin/zapret-ng` - CLI клиент

## Конфигурация

Создайте файл конфигурации на основе примера:

```bash
cp configs/config.example.yaml /etc/zapret-ng/config.yaml
```

Пример конфигурации:

```yaml
server:
  # Unix socket (по умолчанию)
  socket_path: "/run/zapret/zapret-daemon.sock"

  # Сетевой адрес (опционально)
  # network_address: "localhost:8080"

  socket_permissions: 0660

logging:
  level: "info"    # debug, info, warn, error
  format: "text"   # text, json
```

### Переменные окружения

Конфигурацию можно переопределить через переменные окружения:

```bash
ZAPRET_SOCKET_PATH=/tmp/zapret.sock
ZAPRET_NETWORK_ADDRESS=:8080
ZAPRET_LOG_LEVEL=debug
ZAPRET_LOG_FORMAT=json
```

## Использование

### Запуск демона

```bash
# С конфигом по умолчанию (/etc/zapret-ng/config.yaml)
./out/bin/zapret-daemon serve

# С произвольным конфигом
./out/bin/zapret-daemon serve --config /path/to/config.yaml
```

### CLI команды

```bash
# Перезапустить демон
./out/bin/zapret-ng restart

# Принудительный перезапуск
./out/bin/zapret-ng restart --force

# С указанием конкретного сокета
./out/bin/zapret-ng restart --socket /run/zapret/zapret-daemon.sock

# С указанием сетевого адреса
./out/bin/zapret-ng restart --address localhost:8080
```

## Архитектура

```
zapret-discord-youtube-ng/
├── cmd/
│   ├── zapret-daemon/     # Демон-сервис
│   │   ├── main.go
│   │   └── cmd/
│   │       ├── root.go
│   │       └── serve.go
│   └── zapret/            # CLI клиент
│       ├── main.go
│       └── cmd/
│           ├── root.go
│           ├── dialer.go
│           └── restart.go
├── rpc/
│   └── daemon/
│       ├── service.proto       # Protobuf определение
│       ├── service.pb.go       # Сгенерированные сообщения
│       └── service.twirp.go    # Сгенерированный Twirp сервер/клиент
├── internal/
│   ├── config/            # Конфигурация (cleanenv)
│   │   └── config.go
│   └── daemonserver/      # Реализация RPC сервиса
│       └── server.go
├── configs/
│   └── config.example.yaml
└── Makefile
```

## Разработка

### Генерация protobuf кода

После изменения `rpc/daemon/service.proto`:

```bash
make proto
```

### Форматирование кода

```bash
go fmt ./...
```

### Очистка

```bash
make clean
```

## Технологии

- [Cobra](https://github.com/spf13/cobra) - CLI framework
- [cleanenv](https://github.com/ilyakaznacheev/cleanenv) - конфигурация
- [Twirp](https://github.com/twitchtv/twirp) - RPC framework
- [slog](https://pkg.go.dev/log/slog) - структурированное логирование
- [Protocol Buffers](https://protobuf.dev/) - сериализация

## Best Practices

Проект следует best practices Twirp:

- Protobuf файлы содержат полную документацию
- Отдельные пакеты для RPC определений и реализации
- Всегда возвращаем `twirp.Error` из RPC методов
- Структурированное логирование через hooks
- Поддержка Unix sockets для локальной коммуникации
- Graceful shutdown с таймаутом

## Лицензия

MIT
