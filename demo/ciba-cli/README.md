# ciba-cli — Phase-1 CIBA proof

Throwaway client to prove the FAPI-CIBA + PingOne MFA flow end-to-end *before* building the
autonomous agent and the iOS app. It authenticates as a `private_key_jwt` CIBA client,
sends a backchannel request carrying the payment as RFC 9396 `authorization_details` plus a
`binding_message`, and polls for the delegated token (`sub=bob, act={agent}`).

## Use
```bash
pip install -r requirements.txt

# 1. mint a client key + print the JWK to register on the PingFederate CIBA client:
python ciba.py genkey                     # → ciba-key.pem  + a JWKS to paste into PF

# 2. run the flow (Bob approves the push on his PingOne app):
export PF_BASE=https://<your-pf-host>
export CLIENT_ID=<ciba-client-id>  LOGIN_HINT=<bob-username-or-email>
export AMOUNT=150 FROM=CHK-1001 TO=SAV-1002 CURRENCY=AUD
python ciba.py run --insecure             # --insecure only for a dev PF with a self-signed cert
```

## Config (env)
| var | default | notes |
|-----|---------|-------|
| `PF_BASE` | — | PingFederate base URL |
| `CIBA_ENDPOINT` | `$PF_BASE/as/bc-auth.ciba` | backchannel auth endpoint — **confirm for your PF** |
| `TOKEN_ENDPOINT` | `$PF_BASE/as/token.oauth2` | |
| `CLIENT_ID` | — | the CIBA client registered in PF |
| `LOGIN_HINT` | — | Bob's identifier as PF/PingOne resolves it |
| `SCOPE` | `openid banking:payments:transfer` | |
| `AMOUNT`/`FROM`/`TO`/`CURRENCY` | 150 / CHK-1001 / SAV-1002 / AUD | the RAR payment |

The exact backchannel endpoint path + whether `authorization_details` rides on the CIBA
request are being confirmed against the current PingFederate docs; both are env/flag-driven
so we can adjust without code changes.
