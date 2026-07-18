-- security_headers.lua -- Splice check plugin
--
-- Flags missing hardening response headers. Only meaningful on responses, so it
-- returns "[]" for the request phase. Scans SPLICE_RAW (full serialized message
-- including header lines) case-insensitively.
--
-- Contract: see secret_leak.lua. Returns a JSON array of {severity,title,detail}.

if (SPLICE_PHASE or "") ~= "response" then
  return "[]"
end

local raw = string.lower(SPLICE_RAW or "")

local function has_header(name)
  -- header line: start-of-line, name, colon
  return string.find(raw, "\n" .. name .. ":", 1, true) ~= nil
      or string.find(raw, "^" .. name .. ":") ~= nil
end

local checks = {
  {hdr = "strict-transport-security", sev = "medium", title = "Missing HSTS header"},
  {hdr = "content-security-policy",   sev = "medium", title = "Missing Content-Security-Policy"},
  {hdr = "x-frame-options",           sev = "low",    title = "Missing X-Frame-Options"},
  {hdr = "x-content-type-options",    sev = "low",    title = "Missing X-Content-Type-Options"},
}

local findings = {}
for _, c in ipairs(checks) do
  if not has_header(c.hdr) then
    findings[#findings + 1] =
      '{"severity":"' .. c.sev .. '","title":"' .. c.title ..
      '","detail":"header ' .. c.hdr .. ' not present on ' ..
      (SPLICE_PATH or "?") .. '"}'
  end
end

return "[" .. table.concat(findings, ",") .. "]"
