# Control-path regressions

The defect reproductions have been converted into acceptance tests against the production reader, ChaCha20-Poly1305 implementation, HTTP/2 builders and response readers. `run.py` runs the full sanitizer suite, including a real local Go HTTP/2 server. It contacts no Tailscale server and needs no credentials or board. Go checks the decrypted HTTP/2 layer; the encrypted stream corpus checks framing/authentication separately. Neither proves physical packet forwarding or production authorization.

```sh
python3 alternative/tailnet/docs/control-path-replays/run.py --idf /path/to/esp-idf-v5.5.5
```

Coverage includes every TCP split in HTTP upgrade/msg2/transport traffic, every split of EarlyNoise and its coalesced SETTINGS, delayed data, fatal truncated/authentication errors, two concurrent identities, exactly one ACK per received SETTINGS, registration tails, map receipt, descriptor reservation with a real recovery HTTP request under injected pressure, and persistent journal migration/reboot cases.

Observed at firmware `20c0115` with Go 1.23.5:

```text
Complete input: challenge parsed; SETTINGS retained. PASS
Split input: eight consumed SETTINGS-record bytes discarded; next socket byte=0 (expected record type=4). REPRODUCED
Split challenge input: consumed challenge prefix discarded; no challenge available. REPRODUCED
duplicate=true registered=false mapped=false GOAWAY code=1 plaintext=17 bytes
duplicate=false registered=true mapped=true no GOAWAY
```

The historical duplicate-ACK schedule can finish registration before GOAWAY. Its 17-byte plaintext GOAWAY plus 16-byte Noise tag matches the old captured size without proving the old device's uncaptured numeric code. The current deliberate-duplicate interoperability test captures GOAWAY code 1; the normal production sequence registers and applies a map.
