# Kong OSS gateway image for the demo, bundling the custom authzen-pdp plugin.
#
# The plugin is copied onto Kong's Lua path so KONG_PLUGINS=bundled,authzen-pdp
# can load it. Config is DB-less (declarative), rendered at start from
# kong.yml.template by docker-entrypoint.sh (which substitutes the upstream URLs
# that differ between docker-compose and Railway). The AuthZEN API key is read
# at runtime via Kong's built-in `env` vault (AUTHZEN_API_KEY env var).
FROM kong:3.7

USER root
COPY plugins/authzen-pdp /usr/local/share/lua/5.1/kong/plugins/authzen-pdp
COPY kong.yml.template /kong/kong.yml.template
COPY docker-entrypoint.sh /custom-entrypoint.sh
RUN chmod +x /custom-entrypoint.sh && mkdir -p /kong && chown -R kong /kong
USER kong

ENV KONG_DATABASE=off
ENV KONG_DECLARATIVE_CONFIG=/kong/kong.yml
ENV KONG_PLUGINS=bundled,authzen-pdp
# Listen on both IPv4 (compose) and IPv6 (Railway private networking is IPv6-only).
ENV KONG_PROXY_LISTEN="0.0.0.0:8000, [::]:8000"
ENV KONG_ADMIN_LISTEN="0.0.0.0:8001, [::]:8001"

EXPOSE 8000 8001
ENTRYPOINT ["/custom-entrypoint.sh"]
