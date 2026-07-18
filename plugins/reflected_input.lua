-- reflected_input.lua -- Splice check plugin
--
-- Reflected-input heuristic (a cheap XSS/HTML-injection tripwire): if a query
-- parameter's value shows up verbatim in the response body, the parameter is
-- reflected and worth manual review. Correlated in Splice's graph so a reflected
-- sink can be traced back to the entry point that reaches it.
--
-- Contract: see secret_leak.lua. Returns a JSON array of {severity,title,detail}.

if (SPLICE_PHASE or "") ~= "response" then
  return "[]"
end

local query = SPLICE_QUERY or ""
local body = SPLICE_BODY or ""
if query == "" or body == "" then
  return "[]"
end

local function esc(s)
  s = string.gsub(s, "\\", "\\\\")
  s = string.gsub(s, '"', '\\"')
  s = string.gsub(s, "[\r\n\t]", " ")
  return s
end

local findings = {}
-- Walk key=value&key=value pairs.
for k, v in string.gmatch(query, "([^&=]+)=([^&]+)") do
  -- Only consider values long/distinctive enough to be a meaningful reflection.
  if #v >= 4 and string.find(body, v, 1, true) then
    findings[#findings + 1] =
      '{"severity":"medium","title":"Reflected parameter",' ..
      '"detail":"param ' .. esc(k) .. ' reflected in response body"}'
  end
end

return "[" .. table.concat(findings, ",") .. "]"
