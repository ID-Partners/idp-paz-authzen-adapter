# PingAuthorize (the real Ping Authorize PDP) for the demo.
#
# The Go authzen-adapter proxies AuthZEN evaluations to this server's JSON PDP
# API at https://<host>:1443/governance-engine (and /query).
#
# The license is NOT in git or the image. Railway's build upload ships only
# git-tracked files, so we inject the license at runtime from the PING_LICENSE
# environment variable (set on the Railway service) via entrypoint-license.sh,
# which writes it to LICENSE_DIR and then runs the stock PingAuthorize bootstrap.
#
# No 11.1.0.0 image is published; newest is 11.0.0.2. A license versioned
# 11.1.0.0 is newer than the server, which Ping accepts (license >= server).
ARG PAZ_TAG=11.0.0.2-latest
FROM pingidentity/pingauthorize:${PAZ_TAG}

ENV PING_IDENTITY_ACCEPT_EULA=YES
ENV LICENSE_DIR=/opt/in/instance
ENV MAX_HEAP_SIZE=1g

# world-executable so the image's non-root user can run it (no USER juggling)
COPY --chmod=0755 entrypoint-license.sh /opt/entrypoint-license.sh

EXPOSE 1443
ENTRYPOINT ["/opt/entrypoint-license.sh"]
CMD ["start-server"]
