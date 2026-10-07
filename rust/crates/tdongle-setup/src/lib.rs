//! The setup access point boot mode of the T-Dongle firmware (ADR 0024 of the C firmware), as pure `no_std` logic with host tests.
//!
//! A setup boot runs the open access point `TDongle-XXXXXX` on 192.168.4.1, a captive DNS responder, one HTTP server and nothing else,
//! for at most ten minutes. This crate holds every decision of it; the firmware only moves bytes between sockets and these functions:
//!
//! * [`boot`]: the boot decision ([`boot::SetupBoot::decide`]), the RTC request words, the session timer (countdown, forced exit,
//!   failsafe delay), the access point name and the typestate that keeps a USB network out of a setup boot;
//! * [`dns`]: the captive DNS reply for one datagram;
//! * [`http`]: the `esp_http_server`-compatible request reader;
//! * [`access`]: who may ask for what (peer subnet, own address, `Host`, `Origin`, endpoint and action allowlists, token);
//! * [`router`]: [`router::Portal::serve`], every endpoint of the setup page, answering with a [`response::Response`];
//! * [`response`], [`json`], [`page`], [`scan`]: response bytes, `/command` body parsing and JSON output, the embedded pages, the
//!   nearby-networks list;
//! * [`host`]: the traits the firmware implements ([`host::Clock`], [`host::SetupHost`]).
//!
//! Wiring (see `README` in the crate docs of [`router`]): for each accepted connection create an [`http::Reader`], feed it received
//! bytes, on [`http::Step::Ready`] build a [`router::Conn`] from `getpeername`/`getsockname` and call [`router::Portal::serve`], write the
//! result with [`response::Response::write`]; a datagram on UDP 53 goes to [`dns::serve`]; the control task calls
//! [`router::Portal::tick`] every 20 ms and restarts into normal mode when it says [`router::Tick::Leave`].

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod access;
pub mod boot;
pub mod dns;
pub mod host;
pub mod http;
pub mod json;
pub mod page;
pub mod response;
pub mod router;
pub mod scan;
mod tailnet;
pub mod usb;
