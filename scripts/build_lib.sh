#!/bin/bash

# This script is used to locally build Android .aar library and iOS .xcframework from ctrld source using go mobile tool.

# Requirements:
#   - Android NDK (version 23+)
#   - Android SDK (version 33+)
#   - Xcode 15 + Build tools
#   - Go 1.21
#   - Git
# usage: $ ./build_lib.sh v1.3.4

TAG="$1"
# Hacky way to replace version info.
update_versionInfo() {
    local file="$1/ctrld/cmd/cli/cli.go"
    local tag="$2"
    local commit="$3"
    awk -v tag="$tag" -v commit="$commit" '
        BEGIN { version_updated = 0; commit_updated = 0 }
        /^\tversion/ {
            sub(/= ".+"/, "= \"" tag "\"");
            version_updated = 1;
        }
        /^\tcommit/ {
            sub(/= ".+"/, "= \"" commit "\"");
            commit_updated = 1;
        }
        { print }
        END {
            if (version_updated == 0) {
                print "\tversion = \"" tag "\"";
            }
            if (commit_updated == 0) {
                print "\tcommit = \"" commit "\"";
            }
        }
    ' "$file" > "$file.tmp" && mv "$file.tmp" "$file"
}
export ANDROID_NDK_HOME=~/Library/Android/sdk/ndk/23.0.7599858
mkdir bin
cd bin || exit
root=$(pwd)
# Get source from github and switch to tag
git clone --depth 1 --branch "$TAG" https://github.com/Control-D-Inc/ctrld.git
# Prepare gomobile tool
sourcePath=./ctrld/cmd/ctrld_library
cd $sourcePath || exit
go mod tidy
go install golang.org/x/mobile/cmd/gomobile@latest
go get golang.org/x/mobile/bind
gomobile init
# Prepare build info
buildDir=$root/../build
mkdir -p "$buildDir"
COMMIT=$(git rev-parse HEAD)
update_versionInfo "$root" "$TAG" "$COMMIT"
ldflags="-s -w"
# Build
gomobile bind -target ios/arm64 -ldflags="$ldflags" -o "$buildDir"/ctrld-"$TAG".xcframework || exit
gomobile bind -ldflags="$ldflags" -o "$buildDir"/ctrld-"$TAG".aar || exit
# Clean up
rm -r "$root"
echo "Successfully built Ctrld library $TAG($COMMIT)."