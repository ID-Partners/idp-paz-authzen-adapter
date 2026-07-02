# Kong OSS gateway image for the demo, bundling the custom authzen-pdp plugin.
#
# The plugin is copied onto Kong's Lua path so KONG_PLUGINS=bundled,authzen-pdp
# can load it. Config is DB-less (declarative). The authzen-adapter URL and API
# key are injected at runtime via Kong's built-in `env` vault, which reads the
# AUTHZEN_URL and AUTHZEN_API_KEY environment variables — set by docker-compose
# locally and by Railway in production.
FROM kong:3.7

USER root
COPY plugins/authzen-pdp /usr/local/share/lua/5.1/kong/plugins/authzen-pdp
COPY kong.yml /kong/kong.yml
USER kong

ENV KONG_DATABASE=off
ENV KONG_DECLARATIVE_CONFIG=/kong/kong.yml
ENV KONG_PLUGINS=bundled,authzen-pdp
ENV KONG_PROXY_LISTEN=0.0.0.0:8000
ENV KONG_ADMIN_LISTEN=0.0.0.0:8001
# Surface the custom X-PDP-* headers and denial bodies to clients.
ENV KONG_NGINX_WORKER_PROCESSES=1

EXPOSE 8000 8001
