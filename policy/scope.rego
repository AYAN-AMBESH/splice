# Splice engagement scope / Rules of Engagement, expressed as enforced policy.
#
# This file is the authoritative RoE artifact. Splice evaluates every request
# against it BEFORE the request is allowed to reach the proxy's forwarding path,
# so an out-of-scope host is literally unreachable through the proxy -- not merely
# greyed out in a UI. Every allow/deny is also traceable (policy_trace), which
# makes staying in scope a provable, auditable property of the engagement.
#
# Edit the three data blocks below to re-scope an engagement. Classic Rego
# (partial-rule) syntax is used deliberately for broad OPA compatibility.

package scope

# ---------------------------------------------------------------------------
# Rules of Engagement -- edit per engagement
# ---------------------------------------------------------------------------

# Hosts that are in scope. Requests to any other host are denied.
# ENGAGEMENT: whokilledtulpa.com (authorized by the domain owner).
in_scope_hosts := {
	"whokilledtulpa.com",
	"www.whokilledtulpa.com",
	"127.0.0.1",
	"localhost",
}

# HTTP methods permitted against in-scope hosts. CONNECT is required so HTTPS
# interception can begin; the CONNECT target host is itself scope-checked.
allowed_methods := {"GET", "POST", "PUT", "HEAD", "OPTIONS", "PATCH", "CONNECT"}

# Path prefixes that stay off-limits even on in-scope hosts: destructive or
# session-ending actions a tester must not trigger by accident or by an
# automated scan. Matched as prefixes against the request path.
denied_path_prefixes := [
	"/admin/delete",
	"/account/close",
	"/logout",
]

# ---------------------------------------------------------------------------
# Decision logic -- normally left unchanged
# ---------------------------------------------------------------------------

default allow = false
default host_in_scope = false
default method_ok = false
default path_denied = false
default reason = "unspecified"

host_in_scope {
	in_scope_hosts[input.host]
}

method_ok {
	allowed_methods[input.method]
}

path_denied {
	startswith(input.path, denied_path_prefixes[_])
}

allow {
	host_in_scope
	method_ok
	not path_denied
}

reason = "out-of-scope host" {
	not host_in_scope
}

reason = "method not permitted" {
	host_in_scope
	not method_ok
}

reason = "path explicitly denied" {
	host_in_scope
	method_ok
	path_denied
}

reason = "in scope" {
	allow
}

# Rich, structured decision record returned to Splice for logging, graphing and
# the tamper-evident audit trail.
decision := {
	"allow": allow,
	"host": input.host,
	"method": input.method,
	"path": input.path,
	"host_in_scope": host_in_scope,
	"method_ok": method_ok,
	"path_denied": path_denied,
	"reason": reason,
}
