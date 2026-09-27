# syntax=docker/dockerfile:1
FROM golang:1.27.1-trixie@sha256:433790e515d27dc6003e847e644cc0af956985cf315c1c58a3b73ee2dd305183 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY scripts/licenses.go ./scripts/licenses.go
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/altserver ./cmd/altserver \
    && go run scripts/licenses.go /out/licenses

FROM debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a AS signer
RUN apt-get update && apt-get install -y --no-install-recommends g++ make pkg-config libssl-dev libminizip-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*
COPY third_party/zsign /src/zsign
RUN make -C /src/zsign/build/linux -j2 SYSTEM_MINIZIP=1 VERSION=source && strip /src/zsign/bin/zsign

FROM debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libssl3t64 libstdc++6 libminizip1t64 zlib1g \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 altserver \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /var/lib/altserver --shell /usr/sbin/nologin altserver \
    && mkdir -p /var/lib/altserver /var/cache/altserver \
    && chown 10001:10001 /var/lib/altserver /var/cache/altserver
COPY --from=build /out/altserver /usr/local/bin/altserver
COPY --from=signer /src/zsign/bin/zsign /usr/local/bin/zsign
COPY --from=build /out/licenses /usr/share/doc/altserver/go-dependencies
COPY LICENSE THIRD_PARTY_NOTICES.md /usr/share/doc/altserver/
COPY third_party/zsign/LICENSE /usr/share/doc/altserver/zsign-LICENSE
ENV ALTSERVER_STATE_DIR=/var/lib/altserver ALTSERVER_WORK_DIR=/var/cache/altserver
USER 10001:10001
EXPOSE 8080/tcp 6968/tcp 5353/udp
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 CMD ["altserver", "healthcheck"]
ENTRYPOINT ["altserver"]
CMD ["serve"]
