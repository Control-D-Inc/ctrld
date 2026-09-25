#!/bin/bash
# Build a Docker image and prove the binary its ENTRYPOINT names is actually in it.
#
# The container path has no compile-time link to the build: the image copies an
# artifact whose name comes from scripts/build.sh and starts it by a name spelled
# out in the Dockerfile. Renaming the binary once left both Dockerfiles copying a
# glob that matched nothing and starting a file that did not exist - the image
# built clean and only failed at "docker run". Nothing in the test suite covers
# that, so this does.
#
# Usage: docker-smoke.sh [dockerfile ...]   (default: both docker/Dockerfile*)

set -euo pipefail

dockerfiles=("$@")
if [ ${#dockerfiles[@]} -eq 0 ]; then
  dockerfiles=(docker/Dockerfile docker/Dockerfile.debug)
fi

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd -- "$repo_root"

status=0
for dockerfile in "${dockerfiles[@]}"; do
  tag="ctrld-client-smoke:$(basename "$dockerfile" | tr '[:upper:]' '[:lower:]')"
  echo ">>> building $dockerfile as $tag"
  docker build -q -t "$tag" -f "$dockerfile" .

  # Override the entrypoint rather than appending an argument to it: the image's
  # ENTRYPOINT is "<binary> run", so a bare "docker run <image> --version" asks the
  # run subcommand for a version and starts the proxy instead of exiting. Naming
  # the binary explicitly is also the stronger check - it fails if the file is
  # absent or not executable, which is the regression this guards.
  echo ">>> running $tag entrypoint binary with --version"
  if ! out=$(docker run --rm --entrypoint ./ctrld-client "$tag" --version 2>&1); then
    echo >&2 "FAIL: $dockerfile: could not run the image's entrypoint: $out"
    status=1
    docker image rm -f "$tag" >/dev/null 2>&1 || :
    continue
  fi

  echo "    $out"
  case "$out" in
    "ctrld-client version "*) echo "    OK: $dockerfile" ;;
    *)
      echo >&2 "FAIL: $dockerfile: unexpected --version output: $out"
      status=1
      ;;
  esac
  docker image rm -f "$tag" >/dev/null 2>&1 || :
done

exit "$status"
