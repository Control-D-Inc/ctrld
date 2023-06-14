# Using Debian bullseye for building regular image.
# Using scratch image for minimal image size.
# The final image has:
#
# - Timezone info file.
# - CA certs file.
# - /etc/{passwd,group} file.
# - Non-cgo ctrld binary.
#
# CI_COMMIT_TAG is used to set the version of ctrld binary.
FROM golang:bullseye as base

WORKDIR /app

RUN apt-get update && apt-get install -y upx-ucl

COPY . .

ARG tag=master
ENV CI_COMMIT_TAG=$tag
RUN CGO_ENABLED=0 ./scripts/build.sh linux/amd64

FROM scratch

COPY --from=base /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=base /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=base /etc/passwd /etc/passwd
COPY --from=base /etc/group /etc/group

COPY --from=base /app/ctrld-linux-amd64-nocgo ctrld

ENTRYPOINT ["./ctrld", "run"]
