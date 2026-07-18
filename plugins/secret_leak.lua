-- secret_leak.lua -- Splice check plugin
--
-- Flags credentials/secrets that appear in a message body (usually a response,
-- e.g. a key accidentally echoed back, a token in an error page or JS bundle).
--
-- Splice plugin contract:
--   Input  : globals SPLICE_PHASE, SPLICE_METHOD, SPLICE_HOST, SPLICE_PATH,
--            SPLICE_QUERY, SPLICE_STATUS, SPLICE_BODY, SPLICE_RAW (all strings;
--            injected by Splice as Lua long-bracket literals).
--   Output : a JSON array string of findings, "[]" for none. Each finding is
--            {"severity","title","detail"}.
-- Runs in Splice's sandboxed gopher-lua state (no os/io escape, 5s timeout).

local body = SPLICE_BODY or ""

local function esc(s)
  s = string.gsub(s, "\\", "\\\\")
  s = string.gsub(s, '"', '\\"')
  s = string.gsub(s, "[\r\n\t]", " ")
  return s
end

-- Lua patterns are not full regex; these are deliberately broad markers.
local signatures = {
  {title = "Private key block",          sev = "high",   pat = "%-%-%-%-%-BEGIN [%u ]-PRIVATE KEY%-%-%-%-%-"},
  {title = "AWS access key id",          sev = "high",   pat = "AKIA[0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z][0-9A-Z]+"},
  {title = "AWS secret access key",      sev = "high",   pat = "aws_secret_access_key"},
  {title = "Slack token",                sev = "high",   pat = "xox[baprs]%-[%w%-]+"},
  {title = "Bearer token in body",       sev = "medium", pat = "[Bb]earer%s+[%w%._%-]+"},
  {title = "JSON Web Token",             sev = "medium", pat = "eyJ[%w%-_]+%.eyJ[%w%-_]+%.[%w%-_]+"},
  {title = "Generic api key assignment", sev = "low",    pat = "[Aa][Pp][Ii]_?[Kk][Ee][Yy]%s*[=:]%s*[%w%-_]+"},
}

local findings = {}
for _, s in ipairs(signatures) do
  local m = string.match(body, s.pat)
  if m then
    -- Truncate to avoid dumping a whole key into the report.
    local snippet = string.sub(m, 1, 40)
    findings[#findings + 1] =
      '{"severity":"' .. s.sev .. '","title":"' .. s.title ..
      '","detail":"matched: ' .. esc(snippet) .. '"}'
  end
end

return "[" .. table.concat(findings, ",") .. "]"
