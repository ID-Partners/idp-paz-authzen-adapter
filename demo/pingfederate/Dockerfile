# Staging PF: stock PF 13.0.3 + prod config-archive + license + the REBUILT oidf module (with SD-JWT).
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
COPY --chown=9031:0 pingfederate.lic /opt/in/instance/server/default/conf/pingfederate.lic
COPY --chown=9031:0 oidf.war /opt/in/instance/server/default/deploy/oidf.war
COPY --chown=9031:0 pf-oidf-modules.jar /opt/in/instance/server/default/deploy/pf-oidf-modules.jar
COPY --chown=9031:0 jose4j-0.9.6.jar /opt/in/instance/server/default/deploy/jose4j-0.9.6.jar
COPY --chown=9031:0 oidf-mock-attesters.json /opt/in/instance/server/default/conf/oidf-mock-attesters.json
# Northwind-branded HTML Form login page (native submit button, site theme).
COPY --chown=9031:0 template/html.form.login.template.html /opt/in/instance/server/default/conf/template/html.form.login.template.html
RUN sed -i 's/^pf.http.port=-1/pf.http.port=9080/' /opt/staging/instance/bin/run.properties.subst.default
# Activate the static mock-attester resolver (DEV) — PF loads run.properties entries as sys props.
# Without this the hook falls back to federation resolution and rejects the demo attester.
RUN printf '\noidf.mock.attesters=/opt/out/instance/server/default/conf/oidf-mock-attesters.json\n' >> /opt/staging/instance/bin/run.properties.subst.default
# Federation-gated disclosure (AS side): this AS declares it REQUIRES the workload attributes disclosed,
# so a presentation that withholds them (external / unknown profile) is rejected (insufficient_disclosure).
RUN printf '\noidf.attestation.required.claims=workload\n' >> /opt/staging/instance/bin/run.properties.subst.default
USER 9031:0
# Stock entrypoint: the drop-in-deployer imports data.zip during boot.
