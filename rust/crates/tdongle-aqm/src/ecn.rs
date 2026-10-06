//! ECN classification and marking (RFC 3168) of Ethernet frames. Port of the ECN half of `tdongle_aqm.h`.
//!
//! The functions take the frame as a slice and use its length as the C `len`. Nothing here indexes unchecked: any input, truncated or
//! malformed, yields a defined answer (`NotIp` / `None` / `Other`) and never panics. VLAN tags are not parsed (an 802.1Q frame is `NotIp`, so never touched).

/// Class of an Ethernet frame for the purposes of congestion signalling (`tdongle_ecn_class_t`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EcnClass {
    /// Not IPv4/IPv6 (ARP, ...), or malformed: never marked, never dropped.
    NotIp,
    /// IP, but never signalled: connection setup/teardown, DHCP, ICMPv6 neighbour discovery and the like.
    Exempt,
    /// IP, may be dropped, cannot be marked.
    NotEct,
    /// ECT(0) or ECT(1): can be marked CE.
    Capable,
    /// Already CE: a router cannot mark it again, and a signal for it is satisfied.
    Ce,
}

/// Result of [`tcp_ecn_syn`] (`tdongle_tcp_ecn_syn_t`; the discriminants equal the C values).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TcpEcnSyn {
    /// Anything else.
    Other = 0,
    /// SYN with ECE and CWR: the initiator asks for ECN.
    SynEcnSetup = 1,
    /// SYN+ACK with ECE and CWR clear: the server accepts ECN.
    SynAckEcnAccept = 2,
}

fn at(f: &[u8], i: usize) -> Option<u8> {
    f.get(i).copied()
}

fn be16(f: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([at(f, i)?, at(f, i + 1)?]))
}

fn ethertype(f: &[u8]) -> Option<u16> {
    be16(f, 12)
}

/// IPv6: walk the extension headers (hop-by-hop 0, routing 43, fragment 44, authentication 51, destination options 60) to the transport header
/// (`tdongle_ip6_l4`).
///
/// Bounded (at most 6 headers) and bounds-checked against the frame length at every step. Returns `None` for a chain that is malformed,
/// truncated or too long (the caller treats the frame as not IP: never touched). On success returns `(proto, off)`: the final next-header value
/// and the offset of that header in the frame, or `proto == 0xff` when the transport header is not present or not readable (a non-first
/// fragment, ESP, no next header): such a frame is still IP and may be signalled by its ECN field. The caller must have checked that the frame
/// is IPv6 (`len >= 54`, version 6); on a shorter slice this returns `None`.
#[must_use]
pub fn ip6_l4(frame: &[u8]) -> Option<(u8, usize)> {
    let len = frame.len();
    let mut next = at(frame, 20)?;
    let mut o = 14 + 40;
    for depth in 0..=6 {
        if matches!(next, 0 | 43 | 60 | 44 | 51) {
            if depth == 6 || o + 8 > len {
                return None; // a seventh extension header, or one that does not fit
            }
            let hl = match next {
                44 => {
                    if (u16::from(at(frame, o + 2)?) << 5) | (u16::from(at(frame, o + 3)?) >> 3)
                        != 0
                    {
                        return Some((0xff, o)); // non-first fragment: no transport header here
                    }
                    8
                }
                51 => (usize::from(at(frame, o + 1)?) + 2) * 4,
                _ => (usize::from(at(frame, o + 1)?) + 1) * 8,
            };
            next = at(frame, o)?;
            o += hl;
            if o > len {
                return None;
            }
            continue;
        }
        if next == 50 || next == 59 {
            return Some((0xff, o)); // ESP: opaque; no next header
        }
        return Some((next, o));
    }
    None
}

/// Classify an Ethernet frame (`tdongle_ecn_classify`). Reads only what it needs, trusts no length.
///
/// Exempt (never signalled): TCP with FIN, SYN or RST set (first fragment only), UDP to or from ports 67/68 (DHCP, first fragment only),
/// ICMPv6 (also behind extension headers), TCP over IPv6 with FIN/SYN/RST, UDP over IPv6 to port 546/547 (DHCPv6).
#[must_use]
pub fn classify(frame: &[u8]) -> EcnClass {
    classify_inner(frame).unwrap_or(EcnClass::NotIp)
}

fn classify_inner(f: &[u8]) -> Option<EcnClass> {
    let len = f.len();
    if len < 14 {
        return Some(EcnClass::NotIp);
    }
    let ty = ethertype(f)?;
    let ecn = if ty == 0x0800 && len >= 14 + 20 && (at(f, 14)? >> 4) == 4 {
        let ihl = usize::from(at(f, 14)? & 0x0f) * 4;
        let proto = at(f, 23)?;
        if ihl < 20 || 14 + ihl > len {
            return Some(EcnClass::NotIp);
        }
        // Fragment offset (13 bits): only the first fragment carries a transport header.
        let frag = (u16::from(at(f, 20)? & 0x1f) << 8) | u16::from(at(f, 21)?);
        if proto == 6 && frag == 0 && len >= 14 + ihl + 14 && at(f, 14 + ihl + 13)? & 0x07 != 0 {
            return Some(EcnClass::Exempt); // FIN, SYN, RST: connection setup and teardown
        }
        if proto == 17 && frag == 0 && len >= 14 + ihl + 4 {
            let src = be16(f, 14 + ihl)?;
            let dst = be16(f, 14 + ihl + 2)?;
            if dst == 67 || dst == 68 || src == 67 || src == 68 {
                return Some(EcnClass::Exempt); // DHCP
            }
        }
        at(f, 15)? & 3
    } else if ty == 0x86dd && len >= 14 + 40 && (at(f, 14)? >> 4) == 6 {
        let (next, o) = ip6_l4(f)?;
        if next == 58 {
            return Some(EcnClass::Exempt); // ICMPv6: neighbour discovery, MLD, router advertisements (also behind extension headers)
        }
        if next == 6 && o + 14 <= len && at(f, o + 13)? & 0x07 != 0 {
            return Some(EcnClass::Exempt);
        }
        if next == 17 && o + 4 <= len {
            let dst = be16(f, o + 2)?;
            if dst == 546 || dst == 547 {
                return Some(EcnClass::Exempt); // DHCPv6
            }
        }
        (at(f, 15)? >> 4) & 3
    } else {
        return Some(EcnClass::NotIp);
    };
    Some(match ecn {
        0 => EcnClass::NotEct,
        3 => EcnClass::Ce,
        _ => EcnClass::Capable,
    })
}

/// Set CE on an [`EcnClass::Capable`] frame, in place (`tdongle_ecn_mark_ce`).
///
/// IPv4: the header checksum is corrected incrementally (RFC 1624 eqn 3: `HC' = ~(~HC + ~m + m')`), so it is valid afterwards without a pass
/// over the header. IPv6 has no header checksum, and neither TCP's nor UDP's pseudo header covers the ECN field: `|= 0x30` on byte 15.
/// The C original trusts the caller to pass only `Capable` frames; this version additionally leaves a frame too short to hold the fields
/// untouched instead of reading out of bounds. Like C, any ethertype other than 0x0800 is treated as IPv6.
pub fn mark_ce(frame: &mut [u8]) {
    let Some(ty) = ethertype(frame) else { return };
    if ty == 0x0800 {
        let Some(hdr) = frame.get_mut(14..26) else {
            return;
        };
        let m = u16::from_be_bytes([hdr[0], hdr[1]]); // the 16-bit word holding version/IHL and TOS
        let m2 = m | 3;
        let mut sum = u32::from(!u16::from_be_bytes([hdr[10], hdr[11]]));
        sum += u32::from(!m);
        sum += u32::from(m2);
        sum = (sum & 0xffff) + (sum >> 16);
        sum = (sum & 0xffff) + (sum >> 16);
        let hc = !(sum as u16);
        hdr[1] |= 3;
        [hdr[10], hdr[11]] = hc.to_be_bytes();
    } else if let Some(b) = frame.get_mut(15) {
        *b |= 0x30; // ECN bits are bits 5..4 of the second byte of the header
    }
}

/// ECN negotiation, for diagnosis (the board's first CoDel sweep marked nothing: was ECN ever negotiated through this path?)
/// (`tdongle_tcp_ecn_syn`).
///
/// RFC 3168: an initiator asks with SYN+ECE+CWR, a server that accepts answers SYN+ACK+ECE (CWR clear). Anything else: [`TcpEcnSyn::Other`].
/// IPv4 (first fragments only) and IPv6 (extension headers walked by [`ip6_l4`]).
#[must_use]
pub fn tcp_ecn_syn(frame: &[u8]) -> TcpEcnSyn {
    tcp_ecn_syn_inner(frame).unwrap_or(TcpEcnSyn::Other)
}

fn tcp_ecn_syn_inner(f: &[u8]) -> Option<TcpEcnSyn> {
    let len = f.len();
    if len < 14 {
        return Some(TcpEcnSyn::Other);
    }
    let ty = ethertype(f)?;
    let flags = if ty == 0x0800 && len >= 14 + 20 && (at(f, 14)? >> 4) == 4 {
        let ihl = usize::from(at(f, 14)? & 0x0f) * 4;
        if ihl < 20
            || at(f, 23)? != 6
            || 14 + ihl + 14 > len
            || ((u16::from(at(f, 20)? & 0x1f) << 8) | u16::from(at(f, 21)?)) != 0
        {
            return Some(TcpEcnSyn::Other);
        }
        at(f, 14 + ihl + 13)?
    } else if ty == 0x86dd && len >= 14 + 40 && (at(f, 14)? >> 4) == 6 {
        let (next, o) = ip6_l4(f)?;
        if next != 6 || o + 14 > len {
            return Some(TcpEcnSyn::Other);
        }
        at(f, o + 13)?
    } else {
        return Some(TcpEcnSyn::Other);
    };
    let (syn, ack, ece, cwr) = (
        flags & 0x02 != 0,
        flags & 0x10 != 0,
        flags & 0x40 != 0,
        flags & 0x80 != 0,
    );
    Some(if syn && !ack && ece && cwr {
        TcpEcnSyn::SynEcnSetup
    } else if syn && ack && ece && !cwr {
        TcpEcnSyn::SynAckEcnAccept
    } else {
        TcpEcnSyn::Other
    })
}
