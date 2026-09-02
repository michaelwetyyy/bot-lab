FROM caddy:2.11.4-builder-alpine@sha256:7bac9be4072f7c4db2ccc7350750e0705004bf02da2ac7d96b1469ca4f28bb7c AS builder

RUN xcaddy build v2.11.4 \
    --with github.com/hslatman/caddy-crowdsec-bouncer/http@v0.14.0 \
    --with github.com/hslatman/caddy-crowdsec-bouncer/appsec@v0.14.0

FROM caddy:2.11.4-alpine@sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648

COPY --from=builder /usr/bin/caddy /usr/bin/caddy
COPY Caddyfile /etc/caddy/Caddyfile
RUN setcap -r /usr/bin/caddy

USER 1000:1000
EXPOSE 8080
ENTRYPOINT ["caddy"]
CMD ["run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
