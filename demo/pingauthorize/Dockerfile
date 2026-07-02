# PingAuthorize (the real Ping Authorize PDP) for the demo.
#
# The Go authzen-adapter proxies AuthZEN evaluations to this server's JSON PDP
# API at https://<host>:1443/governance-engine (and /query). The license file is
# supplied at deploy time as PingAuthorize.lic in this directory (git-ignored)
# and copied into the server-profile instance dir; it is NOT committed.
#
# Override the image tag to match your license version:
#   docker build --build-arg PAZ_TAG=<tag> .
ARG PAZ_TAG=latest
FROM pingidentity/pingauthorize:${PAZ_TAG}

# Accept the EULA and supply the license via the server-profile instance dir.
ENV PING_IDENTITY_ACCEPT_EULA=YES
ENV LICENSE_DIR=/opt/in/instance
ENV MAX_HEAP_SIZE=1g

# License (kept out of git; present in the deploy upload/build context).
COPY PingAuthorize.lic /opt/in/instance/PingAuthorize.lic

# NOTE: the demo Trust Framework + policy (returning {authorised, reason} for
# domain=idpartners/service=AuthZEN) is added here after the base server is up
# and its live PDP response shape has been confirmed:
#   COPY profile /opt/in

EXPOSE 1443
