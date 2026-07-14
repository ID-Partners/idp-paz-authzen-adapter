# Staging PF: stock PF 13.0.3 + prod config-archive + the REBUILT oidf module (with SD-JWT).
# LICENSING: DevOps-licensed — no pingfederate.lic is baked. The stock image's startup hooks
# fetch a fresh 30-day eval license when PING_IDENTITY_DEVOPS_USER / PING_IDENTITY_DEVOPS_KEY
# (+ PING_IDENTITY_ACCEPT_EULA=YES) are set as Railway service vars and NO license file exists.
# Every restart/redeploy re-fetches, so licenses never need re-baking. Do NOT re-add a
# COPY pingfederate.lic line: an existing file takes precedence and disables the DevOps fetch.
FROM pingidentity/pingfederate:13.0.3-alpine_3.23.4-al21-latest
USER root
# Config restore via PF's native drop-in-deployer: the DataDeployer timer
# (running inside the JVM with system authority) imports any data.zip dropped
# here on boot — no admin API, no license-acceptance gate, no admin password.
# ForceImport/ForceUnsupportedImport are set in the DataDeployer.xml overlay
# below, and the master-key overlay lets prod's encrypted secrets decrypt.
COPY --chown=9031:0 data.zip /opt/in/instance/server/default/data/drop-in-deployer/data.zip
# Overlay prod's master key + system keys BEFORE the deployer runs, so prod's encrypted
# secrets decrypt natively (running master key == archive key; no re-encryption needed).
COPY --chown=9031:0 overlay/pf.jwk /opt/in/instance/server/default/data/pf.jwk
COPY --chown=9031:0 overlay/pingfederate-system-keys.xml /opt/in/instance/server/default/data/pingfederate-system-keys.xml
# Force import: the raw-zipped archive carries no version stamp; both sides are 13.0.3.
COPY --chown=9031:0 overlay/config-store/org.sourceid.saml20.domain.mgmt.impl.DataDeployer.xml /opt/in/instance/server/default/data/config-store/org.sourceid.saml20.domain.mgmt.impl.DataDeployer.xml
COPY --chown=9031:0 oidf.war /opt/in/instance/server/default/deploy/oidf.war
COPY --chown=9031:0 pf-oidf-modules.jar /opt/in/instance/server/default/deploy/pf-oidf-modules.jar
COPY --chown=9031:0 jose4j-0.9.6.jar /opt/in/instance/server/default/deploy/jose4j-0.9.6.jar
# RFC 9396 RAR AuthorizationDetailProcessor → Ping Authorize governance engine.
# Self-contained uber-jar: jackson is shaded + relocated INTO the plugin jar, so
# it resolves on the plugin's own classloader regardless of PF's per-deploy-jar
# isolation (separate jackson jars in deploy/ did not link).
COPY --chown=9031:0 pf.plugins.pf-rar-paz-plugin.jar /opt/in/instance/server/default/deploy/pf.plugins.pf-rar-paz-plugin.jar
COPY --chown=9031:0 oidf-mock-attesters.json /opt/in/instance/server/default/conf/oidf-mock-attesters.json
# PingOne MFA Integration Kit v4.0 (Ping Marketplace, gated download — kept out of git,
# uploaded to the build via `railway up --no-gitignore`). Provides the PingOne MFA CIBA
# Authenticator (PF-INF/oob-auth-plugins → com.pingidentity.oobauth.pingone.mfa.
# PingOneMfaCibaAuthenticator): turns a FAPI-CIBA backchannel request into a PingOne MFA
# push to Bob's phone. Merge its dist tree into the instance exactly as Ping documents.
COPY --chown=9031:0 pf-pingone-mfa-integration-kit-4.0.zip /tmp/mfa-ik.zip
RUN apk add --no-cache unzip \
    && unzip -q /tmp/mfa-ik.zip -d /tmp/mfa-ik \
    && cp -a /tmp/mfa-ik/pf-pingone-mfa-integration-kit/dist/pingfederate/server/default/. \
             /opt/in/instance/server/default/ \
    && chown -R 9031:0 /opt/in/instance/server/default/deploy /opt/in/instance/server/default/conf \
    && rm -rf /tmp/mfa-ik /tmp/mfa-ik.zip \
    && ls /opt/in/instance/server/default/deploy/pf-pingone-mfa-adapter-4.0.jar
# Northwind-branded HTML Form login page (native submit button, site theme).
COPY --chown=9031:0 template/html.form.login.template.html /opt/in/instance/server/default/conf/template/html.form.login.template.html
# OAuth approval/consent page: posts to the same public origin (PF's $action uses
# the internal runtime baseUrl on Railway). Renders scopes + the payment RAR.
COPY --chown=9031:0 template/oauth.approval.page.template.html /opt/in/instance/server/default/conf/template/oauth.approval.page.template.html
RUN sed -i 's/^pf.http.port=-1/pf.http.port=9080/' /opt/staging/instance/bin/run.properties.subst.default
# Activate the static mock-attester resolver (DEV) — PF loads run.properties entries as sys props.
# Without this the hook falls back to federation resolution and rejects the demo attester.
RUN printf '\noidf.mock.attesters=/opt/out/instance/server/default/conf/oidf-mock-attesters.json\n' >> /opt/staging/instance/bin/run.properties.subst.default
# Federation-gated disclosure (AS side): this AS declares it REQUIRES the workload attributes disclosed,
# so a presentation that withholds them (external / unknown profile) is rejected (insufficient_disclosure).
RUN printf '\noidf.attestation.required.claims=workload\n' >> /opt/staging/instance/bin/run.properties.subst.default
# The RAR plugin calls PingAuthorize over its self-signed internal TLS (SAN doesn't
# match *.railway.internal). A trust-all SSLContext doesn't stop the JDK HttpClient's
# in-handshake hostname check; this JDK flag disables it. The image's entrypoint clears
# a container-level JAVA_OPTS, so inject it directly into run.sh's arg list (right after
# PF's own --add-opens line) instead of via ENV.
RUN sed -i '/add-opens=java.base\/java.lang=ALL-UNNAMED/a JAVA_OPTS="$JAVA_OPTS -Djdk.internal.httpclient.disableHostnameVerification=true"' /opt/server/bin/run.sh \
    && grep -c disableHostnameVerification /opt/server/bin/run.sh
USER 9031:0
# Stock entrypoint: the drop-in-deployer imports data.zip during boot.
