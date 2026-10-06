//! The captive DNS responder (`main/captive_dns.c`, `setup_dns_task` of `setup_ap.inc`).
//!
//! Every name resolves to the dongle (192.168.4.1). Only a plain single-question query is answered: an A/IN query gets one A record
//! (TTL 60), any other type or class gets an empty NOERROR answer. Responses, other opcodes, several questions, compressed or invalid
//! labels and anything truncated are ignored (`None`). The answer never copies more than the question.

/// `uint8_t query[256]` of `setup_dns_task`: a longer datagram is cut by `recvfrom`.
pub const QUERY_MAX: usize = 256;
/// `uint8_t reply[256 + 16]`.
pub const REPLY_MAX: usize = QUERY_MAX + 16;
/// The dongle's address on the setup network.
pub const DONGLE: [u8; 4] = [192, 168, 4, 1];

const HEADER: usize = 12;
const ANSWER_BYTES: usize = 16;

/// `captive_dns_reply`: the reply length written to `out`, or `None` to send nothing.
#[must_use]
pub fn reply(q: &[u8], out: &mut [u8], answer_ipv4: [u8; 4]) -> Option<usize> {
    let n = q.len();
    if n < HEADER + 5 {
        return None;
    }
    let flags = u16::from(q[2]) << 8 | u16::from(q[3]);
    if flags & 0x8000 != 0 || (flags >> 11) & 15 != 0 {
        return None;
    }
    if (u16::from(q[4]) << 8 | u16::from(q[5])) != 1 {
        return None;
    }
    let mut i = HEADER;
    while i < n && q[i] != 0 {
        if q[i] > 63 {
            return None;
        }
        i += usize::from(q[i]) + 1;
    }
    if i + 5 > n {
        return None;
    }
    let qtype = u16::from(q[i + 1]) << 8 | u16::from(q[i + 2]);
    let qclass = u16::from(q[i + 3]) << 8 | u16::from(q[i + 4]);
    let question_end = i + 5;
    let answer = qtype == 1 && qclass == 1;
    let total = question_end + if answer { ANSWER_BYTES } else { 0 };
    if total > out.len() {
        return None;
    }
    out[..question_end].copy_from_slice(&q[..question_end]);
    out[2] = 0x80 | (q[2] & 0x01);
    out[3] = 0x80;
    out[4] = 0;
    out[5] = 1;
    out[6] = 0;
    out[7] = u8::from(answer);
    out[8..12].fill(0);
    if answer {
        const RECORD: [u8; 12] = [0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4];
        out[question_end..question_end + 12].copy_from_slice(&RECORD);
        out[question_end + 12..total].copy_from_slice(&answer_ipv4);
    }
    Some(total)
}

/// What `setup_dns_task` does with one received datagram: cut it to [`QUERY_MAX`] like `recvfrom` into a 256 byte buffer, answer with
/// the dongle's address. The reply is `out[..n]`.
#[must_use]
pub fn serve(datagram: &[u8], out: &mut [u8; REPLY_MAX]) -> Option<usize> {
    reply(&datagram[..datagram.len().min(QUERY_MAX)], out, DONGLE)
}
