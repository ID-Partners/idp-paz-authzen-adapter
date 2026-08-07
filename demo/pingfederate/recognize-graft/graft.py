#!/usr/bin/env python3
"""Graft the Recognize User Authorization ATM into an EXISTING PingFederate config archive.

Why grafting rather than deploying our own archive: production PF's live config has drifted from
every on-disk context (it is the agentic build; demo/pingfederate/ has moved ahead of it and adds
clients the live server does not have). Overwriting prod with our archive would silently drop
config that exists nowhere else. The same trap already bit once on staging, where a straight
export would have reverted the Entra client's entraUserToAgentTE policy.

So: export the archive FROM the live server, run this against it, deploy the result. Three
surgical edits, nothing else touched.

    python3 graft.py live-export.zip grafted.zip

Verify afterwards with --check, which re-opens the output and asserts all three edits landed.
"""
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

FRAG = Path(__file__).parent / "fragments"
ATM_ID = "recognizeUserAuthATM"
ATM_FILE = f"bearer-access-token-management-plugins/{ATM_ID}.xml"
REGISTRY = "config-store/bearer-access-token-management-plugins.xml"
SETTINGS = "oauth-authz-server-settings.xml"


def graft(src: Path, dst: Path) -> None:
    work = Path(tempfile.mkdtemp(prefix="pfgraft-"))
    with zipfile.ZipFile(src) as z:
        before = len(z.namelist())
        z.extractall(work)

    if (work / ATM_FILE).exists():
        sys.exit(f"REFUSING: {src.name} already contains {ATM_ID} — nothing to graft.")

    # 1. the ATM instance itself
    (work / ATM_FILE).parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(FRAG / f"{ATM_ID}.xml", work / ATM_FILE)

    # 2. the registry: TWO maps — instance-id→hash and instance-id→plugin class. Each entry is
    #    appended before its own </con:map>, in order, so the Nth close gets the Nth entry.
    reg_path = work / REGISTRY
    reg = reg_path.read_text()
    if ATM_ID in reg:
        sys.exit(f"REFUSING: {REGISTRY} already references {ATM_ID}.")
    entries = [l for l in (FRAG / "registry-entry.xml").read_text().splitlines() if l.strip()]
    if len(entries) != 2:
        sys.exit(f"expected 2 registry entries, found {len(entries)}")
    parts = reg.split("</con:map>")
    if len(parts) < 3:
        sys.exit(f"unexpected {REGISTRY} shape: {len(parts)-1} maps, expected >= 2")
    reg = (parts[0] + entries[0] + "\n</con:map>"
           + parts[1] + entries[1] + "\n</con:map>"
           + "</con:map>".join(parts[2:]))
    reg_path.write_text(reg)

    # 3. the access-token mapping, appended as the last UserKeyToAccessTokenMapping
    set_path = work / SETTINGS
    st = set_path.read_text()
    if ATM_ID in st:
        sys.exit(f"REFUSING: {SETTINGS} already references {ATM_ID}.")
    mapping = (FRAG / "mapping.xml").read_text().strip()
    idx = st.rfind("</urn:UserKeyToAccessTokenMapping>")
    if idx < 0:
        sys.exit(f"no UserKeyToAccessTokenMapping found in {SETTINGS}")
    end = idx + len("</urn:UserKeyToAccessTokenMapping>")
    set_path.write_text(st[:end] + mapping + st[end:])

    # Repack with -D: without it you get extra directory entries and the archive no longer
    # matches PingFederate's own export format.
    if dst.exists():
        dst.unlink()
    subprocess.run(["zip", "-qrD", str(dst.resolve()), "."], cwd=work, check=True)
    shutil.rmtree(work, ignore_errors=True)

    with zipfile.ZipFile(dst) as z:
        after = len(z.namelist())
    print(f"  in : {src.name}  {before} entries")
    print(f"  out: {dst.name}  {after} entries  (+{after - before})")


def check(path: Path) -> int:
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        reg = z.read(REGISTRY).decode()
        st = z.read(SETTINGS).decode()
    ok = {
        "ATM instance file present": ATM_FILE in names,
        "registry has 2 entries": reg.count(ATM_ID) == 2,
        "settings has the mapping": st.count(ATM_ID) == 1,
    }
    for k, v in ok.items():
        print(f"  [{'ok' if v else 'FAIL'}] {k}")
    return 0 if all(ok.values()) else 1


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--check":
        sys.exit(check(Path(sys.argv[2])))
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    graft(Path(sys.argv[1]), Path(sys.argv[2]))
    sys.exit(check(Path(sys.argv[2])))
