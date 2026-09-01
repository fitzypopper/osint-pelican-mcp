# Compatibility shim: Pelican was previously importable as osint_mcp_server.
# New code should use `pelican.*`. Kept so existing client configs and entry
# points that reference the old module name continue to work.
from pelican import *  # noqa: F401,F403
