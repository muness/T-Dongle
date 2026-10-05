---
id: derp-plaintext-before-tag-needs-review
severity: hard
statement: "Do not release DERP TLS plaintext before the record's authentication tag verifies unless a documented crypto review approves the design; even then, DERP control frames must wait for the tag."
outcome: multi-tailnet-gateway
---

S&T step F2b, sufficiency group B. Production DERP needs TLS with records up to 16 KB: Go `crypto/tls` has no max_fragment_length or record_size_limit, and records grow to full size after 128 KB has been sent. A streaming record layer could cut the per-connection buffer to about one DERP frame. It relies on WireGuard authenticating relayed payloads end to end, but DERP control frames (peer gone, health, ping, server info) have no inner authentication. RFC 5116's AEAD interface returns no plaintext before verification, and BearSSL, mbedTLS and embedded-tls all buffer the whole record. No library sets a precedent for this.
