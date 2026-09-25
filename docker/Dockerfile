# Using Debian bookworm for building regular image.
# Using scratch image for minimal image size.
# The final image has:
#
# - Timezone info file.
# - CA certs file.
# - /etc/{passwd,group} file.
# - Non-cgo ctrld-client binary.
#
# CI_COMMIT_TAG is used to set the version of the ctrld-client binary.
FROM golang:1.25-bookworm AS base

WORKDIR /app

RUN echo "deb http://deb.debian.org/debian bookworm-backports main" | tee /etc/apt/sources.list.d/backports.list
RUN apt update && apt install -t bookworm-backports upx-ucl

COPY . .

ARG tag=master
ENV CI_COMMIT_TAG=$tag
RUN CTRLD_NO_QF=yes CGO_ENABLED=0 ./scripts/build.sh

# Resolve the arch-suffixed build artifact to one fixed path, and fail the build
# if it is not there. A COPY glob that matches nothing does not reliably fail,
# which is how a rename can produce an image whose ENTRYPOINT names a binary the
# image does not contain.
RUN set -eu; \
    set -- ctrld-client-linux-*-nocgo; \
    [ "$#" -eq 1 ] && [ -x "$1" ] || { echo >&2 "no single executable build artifact: $*"; exit 1; }; \
    mv -- "$1" /ctrld-client

FROM scratch

COPY --from=base /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=base /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=base /etc/passwd /etc/passwd
COPY --from=base /etc/group /etc/group

COPY --from=base /ctrld-client ctrld-client

ENTRYPOINT ["./ctrld-client", "run"]
