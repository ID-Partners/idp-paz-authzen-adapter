-- Config schema for the authzen-pdp Kong plugin.
local typedefs = require "kong.db.schema.typedefs"

return {
  name = "authzen-pdp",
  fields = {
    { protocols = typedefs.protocols_http },
    { config = {
        type = "record",
        fields = {
          -- Base URL of the Go authzen-adapter (AuthZEN PDP in front of Ping Authorize).
          -- referenceable so it can be supplied via a {vault://env/...} reference.
          { authzen_url = { type = "string", required = true, referenceable = true } },
          -- Bearer key the adapter expects (its API_KEY env var).
          { authzen_api_key = { type = "string", required = true, referenceable = true } },
          -- Label shown in denials and the X-PDP-PEP response header, e.g. "PEP#2 (Bank API edge)".
          { pep_label = { type = "string", default = "kong-pep" } },
          -- Request-mapping style: "rest" (Resource Server) or "mcp" (MCP edge).
          { style = { type = "string", default = "rest",
                      one_of = { "rest", "mcp" } } },
          -- Reject requests that carry no readable access token.
          { require_token = { type = "boolean", default = true } },
          -- Enforce the DPoP sender-constraint binding (cnf.jkt) on the token.
          { require_dpop = { type = "boolean", default = false } },
        },
      },
    },
  },
}
