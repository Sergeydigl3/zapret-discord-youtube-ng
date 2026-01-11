#!/bin/sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
REPO="Sergeydigl3/zapret-ng"
TEMP_DIR=$(mktemp -d)

# Cleanup on exit
cleanup() {
  rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

# Print colored output
info() {
  echo -e "${GREEN}[INFO]${NC} $1"
}

error() {
  echo -e "${RED}[ERROR]${NC} $1" >&2
}

warn() {
  echo -e "${YELLOW}[WARN]${NC} $1"
}

# Check if running with sudo
check_permissions() {
  if [ "$(id -u)" -ne 0 ]; then
    error "This script needs to be run with sudo"
    exit 1
  fi
}

# Find curl or wget
find_downloader() {
  if command -v curl > /dev/null 2>&1; then
    echo "curl"
  elif command -v wget > /dev/null 2>&1; then
    echo "wget"
  else
    error "Neither curl nor wget found. Please install one of them."
    exit 1
  fi
}

# Download file using curl or wget
download_file() {
  local url=$1
  local output=$2
  local downloader=$3

  if [ "$downloader" = "curl" ]; then
    curl -fL "$url" -o "$output" || return 1
  else
    wget -q "$url" -O "$output" || return 1
  fi
  return 0
}

# Detect system architecture
detect_arch() {
  local machine
  machine=$(uname -m)

  case "$machine" in
    x86_64)
      echo "x86_64"
      ;;
    aarch64)
      echo "aarch64"
      ;;
    arm64)
      echo "aarch64"
      ;;
    armv7l)
      echo "armv7"
      ;;
    armv6l)
      echo "armv6"
      ;;
    i386|i686)
      echo "i386"
      ;;
    *)
      error "Unsupported architecture: $machine"
      exit 1
      ;;
  esac
}

# Check if system is Linux
check_linux() {
  if [ "$(uname -s)" != "Linux" ]; then
    error "This script only supports Linux. For other platforms, download the binary from GitHub releases."
    exit 1
  fi
}

# Detect package manager and distro
detect_package_manager() {
  if command -v apt-get > /dev/null 2>&1; then
    echo "deb"
  elif command -v dnf > /dev/null 2>&1; then
    echo "rpm"
  elif command -v yum > /dev/null 2>&1; then
    echo "rpm"
  elif command -v apk > /dev/null 2>&1; then
    echo "apk"
  elif command -v pacman > /dev/null 2>&1; then
    echo "archlinux"
  else
    error "Could not detect package manager"
    exit 1
  fi
}

# Get latest release version
get_latest_version() {
  local version downloader
  downloader=$1

  if [ "$downloader" = "curl" ]; then
    version=$(curl -s "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/' | sed 's/^v//')
  else
    version=$(wget -q -O - "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/' | sed 's/^v//')
  fi

  if [ -z "$version" ]; then
    error "Failed to fetch latest release version"
    exit 1
  fi

  echo "$version"
}

# Download release package
download_package() {
  local version=$1
  local pm=$2
  local arch=$3
  local downloader=$4
  local filename url

  case "$pm" in
    deb)
      filename="zapret-ng_${version}_${arch}.deb"
      ;;
    rpm)
      filename="zapret-ng-${version}-1.${arch}.rpm"
      ;;
    apk)
      filename="zapret-ng-${version}-r0.${arch}.apk"
      ;;
    archlinux)
      filename="zapret-ng-${version}-1-${arch}.pkg.tar.zst"
      ;;
    *)
      error "Unsupported package manager: $pm"
      exit 1
      ;;
  esac

  url="https://github.com/$REPO/releases/download/v${version}/$filename"

  info "Downloading zapret-ng v$version ($pm package)..." >&2
  info "URL: $url" >&2
  info "Saving to: $TEMP_DIR/$filename" >&2

  if ! download_file "$url" "$TEMP_DIR/$filename" "$downloader"; then
    error "Failed to download package from $url"
    exit 1
  fi

  if [ ! -f "$TEMP_DIR/$filename" ]; then
    error "Downloaded file not found: $TEMP_DIR/$filename"
    exit 1
  fi

  echo "$TEMP_DIR/$filename"
}

# Install package
install_package() {
  local package=$1
  local pm=$2

  if [ ! -f "$package" ]; then
    error "Package file not found: $package"
    exit 1
  fi

  info "Installing package..."

  case "$pm" in
    deb)
      apt-get update
      dpkg -i "$package" || apt-get install -f -y
      ;;
    rpm)
      rpm -ivh "$package" 2>/dev/null || dnf install -y "$package" 2>/dev/null || yum install -y "$package"
      ;;
    apk)
      apk add --allow-untrusted "$package"
      ;;
    archlinux)
      pacman -U --noconfirm "$package"
      ;;
  esac
}

# Verify installation
verify_installation() {
  info "Verifying installation..."

  if command -v zapret > /dev/null 2>&1; then
    local version
    version=$(zapret --version 2>/dev/null || echo "unknown")
    info "Installation successful! Version: $version"
    return 0
  else
    warn "Could not verify installation"
    return 1
  fi
}

# Main installation
main() {
  echo "=========================================="
  echo "   zapret-ng Installer"
  echo "=========================================="
  echo ""

  check_linux
  check_permissions

  local arch pm version package

  local downloader
  downloader=$(find_downloader)

  pm=$(detect_package_manager)
  arch=$(detect_arch)

  info "Detected system: $pm/$arch"

  version=$(get_latest_version "$downloader")
  info "Latest version: v$version"

  package=$(download_package "$version" "$pm" "$arch" "$downloader")

  install_package "$package" "$pm"

  verify_installation

  echo ""
  info "zapret-ng installed successfully!"
  echo "Run 'zapret --help' to get started"
}

main
