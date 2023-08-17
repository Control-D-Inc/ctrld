#!/bin/bash

go=${GOBIN:-go}
executable_name="ctrld"
os_archs=(
    darwin/arm64
    darwin/amd64
    windows/386
    windows/amd64
    windows/arm64
    windows/arm
    linux/amd64
    linux/386
    linux/mips
    linux/mipsle
    linux/mips64
    linux/arm
    linux/arm64
    freebsd/amd64
    freebsd/386
    freebsd/arm
    freebsd/arm64
)

compress() {
  binary=$1

  if [ -z "$binary" ]; then
    echo >&2 "missing binary"
    return 1
  fi

  case "$binary" in
    *-freebsd-*)
      echo >&2 "upx does not work with freebsd binary yet"
      return 0
      ;;
    *-windows-arm*)
      echo >&2 "upx does not work with windows arm/arm64 binary yet"
      return 0
      ;;
    *-darwin-*)
      echo >&2 "upx claims to work with darwin binary, but testing show that it is broken"
      return 0
      ;;
    *-linux-armv*)
      echo >&2 "upx does not work on arm routers"
      return 0
      ;;
    *-linux-mips*)
      echo >&2 "upx does not work on mips routers"
      return 0
      ;;
  esac

  upx -- "$binary"
}

build() {
  goos=$1
  goarch=$2
  ldflags="-s -w -X github.com/Windscribe/ctrld/cmd/cli.version="${CI_COMMIT_TAG:-dev}" -X github.com/Windscribe/ctrld/cmd/cli.commit=$(git rev-parse HEAD)"

  case $3 in
    5 | 6 | 7)
      goarm=$3
      if [ "${goos}${goarm}" = "freebsd5" ]; then
        # freebsd/arm require ARMv6K or above: https://github.com/golang/go/wiki/GoArm#supported-operating-systems
        return
      fi
      binary=${executable_name}-${goos}-${goarch}v${3}
      if [ "$CGO_ENABLED" = "0" ]; then
        binary=${binary}-nocgo
      fi
      GOOS=${goos} GOARCH=${goarch} GOARM=${3} "$go" build -ldflags="$ldflags" -o "$binary" ./cmd/ctrld
      compress "$binary"

      if [ -z "${CTRLD_NO_QF}" ]; then
        binary_qf=${executable_name}-qf-${goos}-${goarch}v${3}
        if [ "$CGO_ENABLED" = "0" ]; then
          binary_qf=${binary_qf}-nocgo
        fi
        GOOS=${goos} GOARCH=${goarch} GOARM=${3} "$go" build -ldflags="$ldflags" -tags=qf -o "$binary_qf" ./cmd/ctrld
        compress "$binary_qf"
      fi
      ;;
    *)
      # GOMIPS is required for linux/mips: https://nileshgr.com/2020/02/16/golang-on-openwrt-mips/
      binary=${executable_name}-${goos}-${goarch}
      if [ "$CGO_ENABLED" = "0" ]; then
        binary=${binary}-nocgo
      fi
      GOOS=${goos} GOARCH=${goarch} GOMIPS=softfloat "$go" build -ldflags="$ldflags" -o "$binary" ./cmd/ctrld
      compress "$binary"

      if [ -z "${CTRLD_NO_QF}" ]; then
        binary_qf=${executable_name}-qf-${goos}-${goarch}
        if [ "$CGO_ENABLED" = "0" ]; then
          binary_qf=${binary_qf}-nocgo
        fi
        GOOS=${goos} GOARCH=${goarch} GOMIPS=softfloat "$go" build -ldflags="$ldflags" -tags=qf -o "$binary_qf" ./cmd/ctrld
        compress "$binary_qf"
      fi
      ;;
  esac
}
echo "Building binaries..."

case $1 in
	all)
    for os_arch in "${os_archs[@]}"; do
      goos=${os_arch%/*}
      goarch=${os_arch#*/}

      case goarch in
        arm)

          echo "Building $goos/$goarch ARM5..."
          build "$goos" "$goarch" "5"

          echo "Building $goos/$goarch ARM6..."
          build "$goos" "$goarch" "6"

          echo "Building $goos/$goarch ARM7..."
          build "$goos" "$goarch" "7"

          ;;
        *)
          echo "Building $goos/$goarch..."
          build "$goos" "$goarch"
          ;;
        esac
    done
    ;;
  linux/armv5)
    goos=${1%/*}
    goarch=${1#*/}
	  echo "Building $goos/$goarch..."
    build "$goos" arm "5"
    ;;
  linux/armv6)
    goos=${1%/*}
    goarch=${1#*/}
	  echo "Building $goos/$goarch..."
    build "$goos" arm "6"
    ;;
  linux/armv7)
    goos=${1%/*}
    goarch=${1#*/}
	  echo "Building $goos/$goarch..."
    build "$goos" arm "7"
    ;;
  freebsd/armv6)
    goos=${1%/*}
    goarch=${1#*/}
	  echo "Building $goos/$goarch..."
    build "$goos" arm "6"
    ;;
  freebsd/armv7)
    goos=${1%/*}
    goarch=${1#*/}
	  echo "Building $goos/$goarch..."
    build "$goos" arm "7"
    ;;
  *)
    goos=${1%/*}
    goarch=${1#*/}
    if [ -z "$goos" ]; then
      goos=$(go env GOOS)
    fi
    if [ -z "$goarch" ]; then
      goarch=$(go env GOARCH)
    fi
	  echo "Building $goos/$goarch..."
    build "$goos" "$goarch"
    ;;
esac

printf 'Done \360\237\221\214\n'
