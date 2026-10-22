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
# The build stage runs on the build host's own platform and cross-compiles
# ctrld for the target platform, so no build step runs under qemu emulation.
# buildx sets BUILDPLATFORM and the TARGET* arguments from --platform, e.g.
# linux/arm/v7 gives TARGETOS=linux, TARGETARCH=arm, TARGETVARIANT=v7.
FROM --platform=$BUILDPLATFORM golang:1.27.3-bookworm AS base

WORKDIR /app

RUN echo "deb http://deb.debian.org/debian bookworm-backports main" | tee /etc/apt/sources.list.d/backports.list
RUN apt update && apt install -t bookworm-backports upx-ucl

COPY . .

ARG tag=master
ENV CI_COMMIT_TAG=$tag
ARG TARGETOS TARGETARCH TARGETVARIANT
# scripts/build.sh takes linux/amd64, linux/arm64 or linux/armv7, and names the
# binary after it: ctrld-linux-amd64-nocgo, ctrld-linux-armv7-nocgo, ...
RUN CGO_ENABLED=0 ./scripts/build.sh "${TARGETOS}/${TARGETARCH}${TARGETVARIANT}"

# Move the binary built for this target to one fixed path, and fail the build
# if it is not there. Check its exact name rather than a glob: a glob can also
# match a binary built for another target, and a COPY glob that matches nothing
# does not fail, which would ship an image without ctrld.
RUN set -eu; \
    bin="ctrld-${TARGETOS}-${TARGETARCH}${TARGETVARIANT}-nocgo"; \
    [ -x "$bin" ] || { echo >&2 "missing build artifact: $bin"; exit 1; }; \
    mv -- "$bin" /ctrld

FROM scratch

COPY --from=base /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=base /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=base /etc/passwd /etc/passwd
COPY --from=base /etc/group /etc/group

COPY --from=base /ctrld ctrld

ENTRYPOINT ["./ctrld", "run"]
