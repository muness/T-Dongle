# embedded-tls 0.19.0, patched for a per-record read buffer (the shared lease)

Vendored unchanged from crates.io (`embedded-tls` 0.19.0, MIT/Apache-2.0, `LICENSE` kept) and used only by `rust/crates/tdongle-tailnet-tls` under its cargo feature `lease`
(`path = "../../vendor/embedded-tls"`, no `[patch.crates-io]`). With the feature off the crate uses the unmodified crates.io 0.19. Nothing was sent upstream; this is a local copy.
Everything added is marked `PATCH`/`PATCH(lease)`. Purely additive: no existing function changed behaviour, the stock `TlsConnection::new`/`open`/`read` path is untouched.

Why: upstream pins a 16,640 B read record buffer (`RecordReader.buf: &'a mut [u8]`) for the connection's whole life, but the data in it is only live from the end of a
record header to the end of that record's decrypt+drain. The reader already reads exactly the 5 byte header and then exactly `content_length` bytes (never past the record),
so between records `pending == 0` and the buffer holds nothing; it can be lent to another connection.

Changes (hunks):

1. `src/record_reader.rs`
   * `RecordReader` gets a field `header: Option<RecordHeader>` (initialised `None` in `new`).
   * `RecordReader::leased()`: a reader with an empty buffer.
   * `RecordReader::wait_header(&mut self, transport)`: reads the 5 byte header with `next_record_header` (no buffer touched), keeps it; idempotent.
   * `RecordReader::read_with_lease(&mut self, lease: &'m mut [u8], transport, key_schedule)`: takes the kept header (or reads it), zeroes `decoded`/`pending`, then runs the
     existing `advance` + `consume` free functions on `lease` instead of `self.buf`. The returned `ServerRecord<'m>` borrows the lease only.
2. `src/connection.rs`: `State::process_leased(...)`, a copy of `process` in which `ServerHello` and `ServerVerify` do `wait_header`, take a guard from the lease provider,
   `read_with_lease`, run `process_server_hello` / `process_server_verify`, drop the guard, and only then `handle_processing_error(...).await` (so no lease is held across
   a write). Every other state delegates to the unchanged `process`.
3. `src/asynch.rs` (`TlsConnection`): `new_leased(delegate, write_buf)`; `open_leased(context, &mut lease_provider)` (as `open`, via `process_leased`); `wait_record()`;
   `read_record_leased(&mut self, lease: &mut [u8]) -> ReadBuffer` (reads the announced record into the lease, decrypts in place with the existing `decrypt_record` +
   `DecryptedReadHandler`, returns the plaintext as a `ReadBuffer` over the lease; it first discards any undrained plaintext of an earlier record, which pointed into a lease that is gone).
4. `src/lib.rs`: `pub trait RecordBufProvider { type Guard<'g>: DerefMut<Target=[u8]>; fn lease(&mut self) -> impl Future<Output = Self::Guard<'_>>; }`, and
   `#![warn(clippy::pedantic)]` becomes `#![allow(clippy::pedantic, clippy::all)]` (so `clippy -D warnings` on a dependant does not lint upstream code).
5. `Cargo.toml`/tree: `rust-toolchain.toml`, `Cargo.toml.orig`, `WINDOWS.md`, `.github` removed; `Cargo.lock` and `tests/` kept (not run here: the crate's own tests need tokio/rustls dev-dependencies).

`unsafe`: upstream has exactly one block (`src/common/decrypted_read_handler.rs:29`, a pointer offset of the decrypted slice inside the record buffer), unchanged and relied on as is (the lease passes its own pointer range); none added. The blocking connection (`blocking.rs`) is not patched (no lease variant).

Not done: the write buffer is not leased (it is 2,048 B, 512 B works; a lease would need the same split for `WriteBuffer`; not worth it next to 16,640 B).

Behavioural contract of the lease: take it only after `wait_record()` returned; hold it until the `ReadBuffer` is drained; the record must arrive within the caller's stall bound
or the connection must be dropped (a cancelled `read_record_leased` leaves the reader mid-record). `tdongle-tailnet-tls::lease` implements this with an embassy-sync mutex and a stall timeout.
