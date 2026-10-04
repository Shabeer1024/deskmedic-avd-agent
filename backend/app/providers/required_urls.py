"""AVD session host required URLs probed by `test_required_urls`.

A fixed, reviewed list - the tool never takes URLs from the caller. These are
the session-host endpoints from Microsoft's "Required FQDNs and endpoints for
Azure Virtual Desktop" that can be tested with a plain TCP/443 connection;
wildcard entries (*.wvd.microsoft.com) are represented by the broker endpoint.
"""

from __future__ import annotations

REQUIRED_URLS: tuple[str, ...] = (
    "login.microsoftonline.com",
    "rdbroker.wvd.microsoft.com",
    "catalogartifact.azureedge.net",
    "gcs.prod.monitoring.core.windows.net",
    "mrsglobalsteus2prod.blob.core.windows.net",
    "wvdportalstorageblob.blob.core.windows.net",
    "oneocsp.microsoft.com",
    "www.microsoft.com",
)
