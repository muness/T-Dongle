//! Leased record parsing must retain progress when its read future is cancelled.
//! A deterministic transport stops at a byte boundary without timers or sockets.

use super::*;
use crate::{Aes128GcmSha256, content_types::ContentType, key_schedule::KeySchedule};
use core::{
    convert::Infallible,
    future::Future,
    pin::Pin,
    task::{Context, Poll, Waker},
};

const WIRE: &[u8] = &[
    ContentType::ApplicationData as u8,
    3,
    3,
    0,
    4,
    0xde,
    0xad,
    0xbe,
    0xef,
    ContentType::ApplicationData as u8,
    3,
    3,
    0,
    2,
    0xaa,
    0xbb,
];

struct PausedRead {
    position: usize,
    available: usize,
}

impl embedded_io::ErrorType for PausedRead {
    type Error = Infallible;
}

impl AsyncRead for PausedRead {
    async fn read(&mut self, dst: &mut [u8]) -> Result<usize, Infallible> {
        core::future::poll_fn(|_| {
            if self.position == self.available {
                return Poll::Pending;
            }
            let n = dst.len().min(self.available - self.position);
            dst[..n].copy_from_slice(&WIRE[self.position..self.position + n]);
            self.position += n;
            Poll::Ready(Ok(n))
        })
        .await
    }
}

fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

fn read_record(reader: &mut RecordReader<'_>, transport: &mut PausedRead, lease: &mut [u8]) {
    let mut keys = KeySchedule::<Aes128GcmSha256>::new();
    let mut future = core::pin::pin!(reader.read_with_lease(lease, transport, keys.read_state()));
    match poll_once(future.as_mut()) {
        Poll::Ready(Ok(ServerRecord::ApplicationData(data))) => {
            assert_eq!(data.data.as_slice(), &[0xde, 0xad, 0xbe, 0xef]);
        }
        Poll::Ready(Err(e)) => panic!("resuming a cancelled read lost TLS record progress: {e:?}"),
        _ => panic!("the complete application record must be available immediately"),
    }
}

fn read_following_record(
    reader: &mut RecordReader<'_>,
    transport: &mut PausedRead,
    lease: &mut [u8],
) {
    let mut keys = KeySchedule::<Aes128GcmSha256>::new();
    let mut future = core::pin::pin!(reader.read_with_lease(lease, transport, keys.read_state()));
    match poll_once(future.as_mut()) {
        Poll::Ready(Ok(ServerRecord::ApplicationData(data))) => {
            assert_eq!(data.data.as_slice(), &[0xaa, 0xbb])
        }
        Poll::Ready(Err(e)) => panic!("the next record failed: {e:?}"),
        _ => panic!("the next record must not be swallowed or duplicated"),
    }
}

#[test]
fn cancelled_partial_header_resumes_without_losing_two_bytes() {
    let mut reader = RecordReader::leased();
    let mut transport = PausedRead {
        position: 0,
        available: 2,
    };
    {
        let mut future = core::pin::pin!(reader.wait_header(&mut transport));
        assert!(poll_once(future.as_mut()).is_pending());
    } // Cancel after two of the five TLS header bytes reached the parser.
    assert_eq!(transport.position, 2);
    transport.available = WIRE.len();
    {
        let mut future = core::pin::pin!(reader.wait_header(&mut transport));
        assert!(
            matches!(poll_once(future.as_mut()), Poll::Ready(Ok(()))),
            "resumed header must retain its consumed prefix"
        );
    }
    assert_eq!(reader.header_len(), Some(4));
    assert_eq!(
        transport.position, 5,
        "header parsing cannot eat body bytes"
    );
    let mut lease = [0; 4];
    read_record(&mut reader, &mut transport, &mut lease);
    assert_eq!(transport.position, 9);
    read_following_record(&mut reader, &mut transport, &mut lease);
    assert_eq!(transport.position, WIRE.len());
}

#[test]
fn cancelled_partial_body_resumes_in_the_same_lease() {
    let mut reader = RecordReader::leased();
    let mut transport = PausedRead {
        position: 0,
        available: 7,
    };
    let mut lease = [0; 4];
    let mut keys = KeySchedule::<Aes128GcmSha256>::new();
    {
        let mut future =
            core::pin::pin!(reader.read_with_lease(&mut lease, &mut transport, keys.read_state()));
        assert!(poll_once(future.as_mut()).is_pending());
    } // Cancel after the full header and two body bytes have arrived.
    assert_eq!(transport.position, 7);
    assert_eq!(&lease[..2], &[0xde, 0xad]);
    transport.available = WIRE.len();
    read_record(&mut reader, &mut transport, &mut lease);
    assert_eq!(transport.position, 9);
    assert_eq!(&lease, &[0xde, 0xad, 0xbe, 0xef]);
    read_following_record(&mut reader, &mut transport, &mut lease);
    assert_eq!(transport.position, WIRE.len());
}
