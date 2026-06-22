# Using Debian bookworm for building regular image.
# Using scratch image for minimal image size.
# The final image has:
#
# - Timezone info file.
# - CA certs file.
# - /etc/{passwd,group} file.
# - Non-cgo ctrld binary.
#
# CI_COMMIT_TAG is used to set the version of ctrld binary.
FROM golang:1.25-bookworm AS base

WORKDIR /app

RUN echo "deb http://deb.debian.org/debian bookworm-backports main" | tee /etc/apt/sources.list.d/backports.list
RUN apt update && apt install -t bookworm-backports upx-ucl

COPY . .

ARG tag=master
ENV CI_COMMIT_TAG=$tag
RUN CTRLD_NO_QF=yes CGO_ENABLED=0 ./scripts/build.sh

FROM scratch

COPY --from=base /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=base /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=base /etc/passwd /etc/passwd
COPY --from=base /etc/group /etc/group

COPY --from=base /app/ctrld-linux-*-nocgo ctrld

ENTRYPOINT ["./ctrld", "run"]
