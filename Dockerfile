# syntax=docker/dockerfile:1

FROM golang:1.19-bookworm AS build

WORKDIR /src

# Keep the default build non-GUI. SiteBrush uses pure-Go database drivers for
# the service path, so CGO can stay disabled for a small static binary.
ENV CGO_ENABLED=0

COPY go.mod go.sum ./
COPY vendor ./vendor
COPY . .

RUN go build -trimpath -ldflags="-s -w" -o /out/sitebrush .

FROM alpine:3.19

RUN addgroup -S sitebrush \
	&& adduser -S -D -H -u 10001 -G sitebrush sitebrush \
	&& mkdir -p /data /public_html \
	&& chown -R sitebrush:sitebrush /data /public_html

COPY --from=build /out/sitebrush /usr/local/bin/sitebrush

USER sitebrush:sitebrush
WORKDIR /home/sitebrush

EXPOSE 2444
VOLUME ["/data", "/public_html"]

ENTRYPOINT ["sitebrush"]
CMD ["-web-path", "/public_html", "-db-path", "/data", "-db-type", "sqlite"]
