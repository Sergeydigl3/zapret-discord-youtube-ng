# Руководство по релизу

Этот проект использует GoReleaser и GitHub Actions для автоматической сборки и публикации пакетов.

## Поддерживаемые форматы пакетов

- **DEB** (Debian, Ubuntu)
- **RPM** (RHEL, CentOS, Fedora, openSUSE)
- **APK** (Alpine Linux)
- **Arch Linux** (Arch, Manjaro)
- **tar.gz** архивы для всех платформ

## Поддерживаемые системы инициализации

Пакеты автоматически определяют и настраивают систему инициализации:

- **systemd** (большинство современных дистрибутивов)
- **OpenRC** (Alpine Linux, Gentoo)
- **SysVinit** (старые версии Debian/Ubuntu)

## Создание релиза

### Автоматический релиз (рекомендуется)

1. Создайте и запушьте тег версии:
   ```bash
   git tag -a v1.0.0 -m "Release v1.0.0"
   git push origin v1.0.0
   ```

2. GitHub Actions автоматически:
   - Соберет бинарники для всех платформ (amd64, arm64, arm, 386)
   - Создаст пакеты (deb, rpm, apk, archlinux)
   - Опубликует релиз на GitHub
   - Сгенерирует checksums

### Локальная сборка

Для тестирования перед релизом:

```bash
# Установить GoReleaser
go install github.com/goreleaser/goreleaser/v2@latest

# Проверить конфигурацию
goreleaser check

# Собрать снапшот (без публикации)
goreleaser release --snapshot --clean

# Пакеты будут в директории out/dist/
ls -la out/dist/
```

## Архитектуры

Поддерживаются следующие архитектуры:
- **amd64** (x86_64)
- **arm64** (aarch64)
- **arm** v6/v7 (armhf)
- **386** (i386)

## Установка пакетов

### Debian/Ubuntu (DEB)

```bash
# Скачать пакет с GitHub Releases
wget https://github.com/Sergeydigl3/zapret-nix/releases/download/v1.0.0/zapret-daemon_1.0.0_amd64.deb

# Установить
sudo dpkg -i zapret-daemon_1.0.0_amd64.deb

# Настроить конфигурацию
sudo nano /etc/zapret/config.yaml

# Запустить сервис (systemd)
sudo systemctl start zapret-daemon
sudo systemctl enable zapret-daemon
sudo systemctl status zapret-daemon

# Или для SysVinit
sudo service zapret-daemon start
sudo service zapret-daemon status
```

### RHEL/CentOS/Fedora (RPM)

```bash
# Скачать пакет
wget https://github.com/Sergeydigl3/zapret-nix/releases/download/v1.0.0/zapret-daemon-1.0.0-1.x86_64.rpm

# Установить
sudo rpm -ivh zapret-daemon-1.0.0-1.x86_64.rpm
# Или с yum/dnf
sudo yum install zapret-daemon-1.0.0-1.x86_64.rpm

# Настроить и запустить
sudo nano /etc/zapret/config.yaml
sudo systemctl start zapret-daemon
sudo systemctl enable zapret-daemon
```

### Alpine Linux (APK)

```bash
# Скачать пакет
wget https://github.com/Sergeydigl3/zapret-nix/releases/download/v1.0.0/zapret-daemon-1.0.0-r0.x86_64.apk

# Установить
sudo apk add --allow-untrusted zapret-daemon-1.0.0-r0.x86_64.apk

# Настроить и запустить (OpenRC)
sudo nano /etc/zapret/config.yaml
sudo rc-service zapret-daemon start
sudo rc-update add zapret-daemon default
```

### Arch Linux

```bash
# Скачать пакет
wget https://github.com/Sergeydigl3/zapret-nix/releases/download/v1.0.0/zapret-daemon-1.0.0-1-x86_64.pkg.tar.zst

# Установить
sudo pacman -U zapret-daemon-1.0.0-1-x86_64.pkg.tar.zst

# Настроить и запустить
sudo nano /etc/zapret/config.yaml
sudo systemctl start zapret-daemon
sudo systemctl enable zapret-daemon
```

### Из архива (tar.gz)

```bash
# Скачать архив
wget https://github.com/Sergeydigl3/zapret-nix/releases/download/v1.0.0/zapret-daemon_1.0.0_linux_x86_64.tar.gz

# Распаковать
tar -xzf zapret-daemon_1.0.0_linux_x86_64.tar.gz

# Установить бинарники
sudo cp zapret-daemon /usr/local/bin/
sudo cp zapret /usr/local/bin/

# Создать конфигурацию
sudo mkdir -p /etc/zapret
sudo cp configs/config.example.yaml /etc/zapret/config.yaml

# Установить init скрипт вручную
# Для systemd:
sudo cp init/systemd/zapret-daemon.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable zapret-daemon
sudo systemctl start zapret-daemon

# Для OpenRC:
sudo cp init/openrc/zapret-daemon /etc/init.d/
sudo chmod +x /etc/init.d/zapret-daemon
sudo rc-update add zapret-daemon default
sudo rc-service zapret-daemon start

# Для SysVinit:
sudo cp init/sysvinit/zapret-daemon /etc/init.d/
sudo chmod +x /etc/init.d/zapret-daemon
sudo update-rc.d zapret-daemon defaults
sudo service zapret-daemon start
```

## Управление сервисом

### Systemd

```bash
# Запустить
sudo systemctl start zapret-daemon

# Остановить
sudo systemctl stop zapret-daemon

# Перезапустить
sudo systemctl restart zapret-daemon

# Статус
sudo systemctl status zapret-daemon

# Логи
sudo journalctl -u zapret-daemon -f
```

### OpenRC

```bash
# Запустить
sudo rc-service zapret-daemon start

# Остановить
sudo rc-service zapret-daemon stop

# Перезапустить
sudo rc-service zapret-daemon restart

# Статус
sudo rc-service zapret-daemon status
```

### SysVinit

```bash
# Запустить
sudo service zapret-daemon start

# Остановить
sudo service zapret-daemon stop

# Перезапустить
sudo service zapret-daemon restart

# Статус
sudo service zapret-daemon status
```

## Удаление

### DEB

```bash
sudo apt remove zapret-daemon
# Или полное удаление с конфигурацией
sudo apt purge zapret-daemon
```

### RPM

```bash
sudo yum remove zapret-daemon
# Или
sudo rpm -e zapret-daemon
```

### APK

```bash
sudo apk del zapret-daemon
```

### Arch

```bash
sudo pacman -R zapret-daemon
```

## Структура файлов после установки

```
/usr/bin/zapret-daemon          # Демон
/usr/bin/zapret                 # CLI клиент
/etc/zapret/config.yaml         # Конфигурация
/var/run/zapret/                # Runtime директория
/usr/lib/systemd/system/zapret-daemon.service  # Systemd unit (если systemd)
/etc/init.d/zapret-daemon       # Init скрипт (если OpenRC/SysVinit)
```

## Скрипты установки

При установке пакета автоматически выполняются:

1. **postinstall.sh** - определяет систему инициализации и настраивает сервис
2. **preremove.sh** - останавливает и удаляет сервис перед деинсталляцией

## CI/CD Pipeline

GitHub Actions автоматически запускается при:
- Пуше тега `v*.*.*`
- Ручном запуске workflow

Этапы:
1. Checkout кода
2. Установка Go и protoc
3. Генерация protobuf кода
4. Запуск GoReleaser
5. Публикация релиза

## Проверка релиза

После создания релиза проверьте:

1. Все пакеты созданы для всех платформ
2. Checksums файл присутствует
3. Release notes сгенерированы
4. Архивы содержат все необходимые файлы

```bash
# Проверить содержимое архива
tar -tzf zapret-daemon_1.0.0_linux_x86_64.tar.gz

# Проверить checksums
sha256sum -c checksums.txt
```

## Troubleshooting

### Ошибка при генерации protobuf

Убедитесь, что protoc установлен и находится в PATH:
```bash
protoc --version
```

### Ошибка при установке пакета

Проверьте зависимости:
```bash
# Debian/Ubuntu
sudo apt install iptables

# RHEL/CentOS
sudo yum install iptables

# Alpine
sudo apk add iptables
```

### Сервис не запускается

Проверьте логи:
```bash
# Systemd
sudo journalctl -u zapret-daemon -xe

# OpenRC
sudo rc-service zapret-daemon status

# Проверьте конфигурацию
sudo zapret-daemon serve --config /etc/zapret/config.yaml
```
