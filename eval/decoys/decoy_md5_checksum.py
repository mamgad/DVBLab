"""
DECOY (SAFE): looks like weak crypto (MD5), but MD5 is used only as a fast
non-security checksum / cache key, never for passwords, tokens, or signatures.

The call is explicitly marked usedforsecurity=False. MD5 here is a content
fingerprint for cache invalidation; collisions have no security impact because
no trust decision depends on the digest. False-positive trap.
"""

import hashlib


def cache_key(content: bytes) -> str:
    # usedforsecurity=False makes the non-security intent explicit.
    # This is a cache bucket key, not a password hash or a signature.
    return hashlib.md5(content, usedforsecurity=False).hexdigest()


def etag_for(blob: bytes) -> str:
    # Same idea: a cheap content fingerprint for HTTP ETag / dedup.
    digest = hashlib.md5(usedforsecurity=False)
    digest.update(blob)
    return digest.hexdigest()
