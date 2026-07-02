-- authzen-pdp: a Kong Policy Enforcement Point (PEP) that calls the AuthZEN PDP.
--
-- For every proxied request this plugin:
--   1. extracts the delegated access token (DPoP or Bearer) and reads its claims
--      (sub = principal, act.sub = acting agent, scope, cnf.jkt);
--   2. if DPoP is required, checks the sender-constraint binding: the SHA-256
--      JWK thumbprint of the DPoP proof header key must equal the access token's
--      cnf.jkt (RFC 9449), and the proof must carry htm/ath;
--   3. builds an AuthZEN evaluation request (subject=agent on behalf of principal,
--      action+resource+context derived from the HTTP request) and POSTs it to the
--      Go authzen-adapter, which asks Ping Authorize;
--   4. PERMIT -> forwards the request, injecting X-Auth-Principal / X-Auth-Agent /
--      X-Auth-Scope for the Resource Server's audit trail;
--      DENY   -> returns 403 with the policy reason.
--
-- NOTE (demo honesty): this plugin reads the JWT claims and enforces the DPoP
-- key binding, but does not itself verify the access-token JWS signature. In a
-- hardened deployment pair this with Kong's bundled `openid-connect`/`jwt` plugin
-- (or set verify against the AS JWKS) so the token signature is validated before
-- these claims are trusted. The authorization decision itself is always made by
-- Ping Authorize via the PDP.

local http = require "resty.http"
local cjson = require "cjson.safe"
local resty_sha256 = require "resty.sha256"

local AuthzenPDP = {
  PRIORITY = 1000,  -- run before upstream proxying; after auth plugins if present
  VERSION = "0.1.0",
}

-- ---------- helpers ----------

local function b64url_decode(str)
  if not str or str == "" then return nil end
  str = str:gsub("-", "+"):gsub("_", "/")
  local pad = #str % 4
  if pad > 0 then str = str .. string.rep("=", 4 - pad) end
  return ngx.decode_base64(str)
end

local function b64url_encode(bytes)
  return (ngx.encode_base64(bytes):gsub("+", "-"):gsub("/", "_"):gsub("=", ""))
end

-- decode the payload (claims) of a compact JWT; returns table or nil
local function jwt_claims(token)
  if not token then return nil end
  local dot1 = token:find("%.")
  if not dot1 then return nil end
  local dot2 = token:find("%.", dot1 + 1)
  if not dot2 then return nil end
  local payload = b64url_decode(token:sub(dot1 + 1, dot2 - 1))
  if not payload then return nil end
  return cjson.decode(payload)
end

-- decode the protected header of a compact JWT; returns table or nil
local function jwt_header(token)
  if not token then return nil end
  local dot1 = token:find("%.")
  if not dot1 then return nil end
  local header = b64url_decode(token:sub(1, dot1 - 1))
  if not header then return nil end
  return cjson.decode(header)
end

-- RFC 7638 JWK thumbprint (SHA-256, base64url) for EC / RSA / OKP keys
local function jwk_thumbprint(jwk)
  if type(jwk) ~= "table" or not jwk.kty then return nil end
  local canon
  if jwk.kty == "EC" then
    canon = string.format('{"crv":"%s","kty":"EC","x":"%s","y":"%s"}', jwk.crv, jwk.x, jwk.y)
  elseif jwk.kty == "RSA" then
    canon = string.format('{"e":"%s","kty":"RSA","n":"%s"}', jwk.e, jwk.n)
  elseif jwk.kty == "OKP" then
    canon = string.format('{"crv":"%s","kty":"OKP","x":"%s"}', jwk.crv, jwk.x)
  else
    return nil
  end
  local sha = resty_sha256:new()
  sha:update(canon)
  return b64url_encode(sha:final())
end

-- extract the access token from Authorization: "DPoP <t>" or "Bearer <t>"
local function extract_token(auth_header)
  if not auth_header then return nil, nil end
  local scheme, token = auth_header:match("^(%a+)%s+(.+)$")
  if not scheme then return nil, nil end
  return token, scheme:lower()
end

local function deny(pep, status, reason)
  return kong.response.exit(status, {
    error = "authorization_failed",
    pep = pep,
    reason = reason,
  }, { ["Content-Type"] = "application/json" })
end

-- Map the HTTP request to an AuthZEN (action, resource, context, resource_props).
-- style="rest": Resource Server semantics (fine-grained, e.g. payment amount).
-- style="mcp" : MCP edge (coarse; refine to the tool name if the JSON-RPC body
--               is a tools/call, otherwise authorize the rpc method generically).
local function map_request(conf)
  local method = kong.request.get_method()
  local path = kong.request.get_path()
  local ctx = { channel = "ai-agent" }
  local action, rtype, rid = nil, nil, nil
  local rprops = {}

  if conf.style == "mcp" then
    -- Only real tool invocations are policy-gated. The MCP handshake
    -- (initialize / tools/list / notifications / ping) and the SSE GET stream
    -- are allowed through on a valid token so an authenticated agent can always
    -- connect; fine-grained policy still applies to tools/call here and to the
    -- banking operations at PEP #2. action=__allow__ signals "skip the PDP".
    rtype, rid, action = "mcp-service", "northwind-bank", "__allow__"
    local ok, body = pcall(function() return kong.request.get_raw_body() end)
    if ok and body then
      local rpc = cjson.decode(body)
      if type(rpc) == "table" and rpc.method == "tools/call"
         and rpc.params and rpc.params.name then
        action = "invoke_tool"
        rtype, rid = "mcp-tool", rpc.params.name
      end
    end
    return action, rtype, rid, rprops, ctx
  end

  -- style == "rest"
  -- Patterns are prefix-tolerant: Kong strips the route prefix (/bank) but the
  -- plugin sees the original request path, so we match without anchoring at ^.
  local cust = path:match("/customers/([^/]+)/accounts")
  local acct = path:match("/accounts/([^/]+)/balance")
  if cust then
    action, rtype, rid = "list_accounts", "customer", cust
  elseif acct then
    action, rtype, rid = "get_balance", "account", acct
  elseif path:match("/accounts") and method == "POST" then
    action, rtype = "open_account", "account"
    local ok, body = pcall(function() return kong.request.get_body() end)
    if ok and type(body) == "table" then
      rid = "new:" .. tostring(body.account_type or "savings")
      rprops.account_type = body.account_type
    else
      rid = "new:savings"
    end
  elseif path:match("/payments") and method == "POST" then
    action, rtype = "make_payment", "account"
    local ok, body = pcall(function() return kong.request.get_body() end)
    if ok and type(body) == "table" then
      rid = tostring(body.from_account or "")
      rprops.from_account = body.from_account
      rprops.to_account = body.to_account
      ctx.amount = tonumber(body.amount)
      ctx.currency = body.currency or "AUD"
      ctx.description = body.description
      if body.internal_transfer ~= nil then
        ctx.internal_transfer = body.internal_transfer
      end
    end
  else
    action, rtype, rid = "http:" .. method:lower(), "endpoint", path
  end
  return action, rtype, rid, rprops, ctx
end

-- ---------- main phase ----------

function AuthzenPDP:access(conf)
  local pep = conf.pep_label or "kong-pep"

  -- 1) token + claims
  local token, scheme = extract_token(kong.request.get_header("authorization"))
  if not token then
    if conf.require_token then
      return deny(pep, 401, "No access token presented to the gateway.")
    end
  end

  local claims = token and jwt_claims(token) or {}
  claims = claims or {}
  local sub = claims.sub
  local act = type(claims.act) == "table" and claims.act.sub or nil
  local scope = claims.scope or claims.scp
  if type(scope) == "table" then scope = table.concat(scope, " ") end
  local client_id = claims.client_id or claims.azp

  if conf.require_token and not sub then
    return deny(pep, 401, "Access token missing or unreadable (no subject claim).")
  end

  -- 2) DPoP sender-constraint binding
  if conf.require_dpop then
    if scheme ~= "dpop" then
      return deny(pep, 401, "DPoP-bound token required but Authorization scheme was not DPoP.")
    end
    local proof = kong.request.get_header("dpop")
    if not proof then
      return deny(pep, 401, "Missing DPoP proof header.")
    end
    local phdr = jwt_header(proof)
    local pclaims = jwt_claims(proof)
    local jkt = phdr and jwk_thumbprint(phdr.jwk)
    local cnf_jkt = type(claims.cnf) == "table" and claims.cnf.jkt or nil
    if not jkt or not cnf_jkt or jkt ~= cnf_jkt then
      return deny(pep, 401, "DPoP proof key does not match the token's cnf.jkt binding.")
    end
    if not pclaims or pclaims.htm ~= kong.request.get_method() then
      return deny(pep, 401, "DPoP proof htm does not match the request method.")
    end
    if not pclaims.ath then
      return deny(pep, 401, "DPoP proof missing ath (access-token hash).")
    end
    -- htu is validated best-effort: hosts get rewritten behind the platform proxy,
    -- so a mismatch is logged rather than fatal for the demo.
    if pclaims.htu and not tostring(pclaims.htu):find(kong.request.get_path(), 1, true) then
      kong.log.warn("DPoP htu path mismatch: ", tostring(pclaims.htu))
    end
  end

  -- 3) build AuthZEN evaluation request
  local action, rtype, rid, rprops, ctx = map_request(conf)

  -- MCP handshake / non-tool traffic: allow on a valid token, skip the PDP.
  if action == "__allow__" then
    kong.service.request.set_header("X-Auth-Principal", sub or "")
    kong.service.request.set_header("X-Auth-Agent", act or "")
    kong.service.request.set_header("X-Auth-Scope", scope or "")
    local c = kong.ctx.plugin
    c.pep, c.decision, c.action = pep, "PERMIT", "mcp-handshake"
    c.reason = "MCP handshake allowed (authenticated); policy applies to tool calls."
    return
  end

  local authzen_req = {
    subject = {
      type = "agent",
      identity = act or client_id or "unknown-agent",
      properties = {
        on_behalf_of = sub,
        agent_type = "ai_assistant",
        scope = scope,
        client_id = client_id,
      },
    },
    action = { name = action },
    resource = { type = rtype, id = rid, properties = rprops },
    context = ctx,
  }

  local httpc = http.new()
  httpc:set_timeout(10000)
  local res, err = httpc:request_uri(conf.authzen_url .. "/access/v1/evaluation", {
    method = "POST",
    body = cjson.encode(authzen_req),
    headers = {
      ["Content-Type"] = "application/json",
      ["Authorization"] = "Bearer " .. (conf.authzen_api_key or ""),
    },
    ssl_verify = false,
  })

  -- 4) enforce (fail closed on PDP error)
  if not res then
    kong.log.err("PDP call failed: ", err)
    return deny(pep, 503, "Authorization service unreachable; denying (fail-closed).")
  end
  local data = cjson.decode(res.body) or {}
  local decision = data.decision == true
  local reason = (type(data.context) == "table" and data.context.reason) or
                 (decision and "Permitted by policy." or "Denied by policy.")

  -- surface the decision on the response for the demo transcript
  local pdp_ctx = kong.ctx.plugin
  pdp_ctx.pep = pep
  pdp_ctx.decision = decision and "PERMIT" or "DENY"
  pdp_ctx.reason = reason
  pdp_ctx.action = action

  if not decision then
    return deny(pep, 403, reason)
  end

  -- PERMIT: pass the delegation identity to the upstream for its audit trail
  kong.service.request.set_header("X-Auth-Principal", sub or "")
  kong.service.request.set_header("X-Auth-Agent", act or "")
  kong.service.request.set_header("X-Auth-Scope", scope or "")
end

function AuthzenPDP:header_filter(conf)
  local c = kong.ctx.plugin
  if c and c.decision then
    kong.response.set_header("X-PDP-PEP", c.pep or "")
    kong.response.set_header("X-PDP-Decision", c.decision)
    kong.response.set_header("X-PDP-Action", c.action or "")
    if c.reason then kong.response.set_header("X-PDP-Reason", c.reason) end
  end
end

return AuthzenPDP
