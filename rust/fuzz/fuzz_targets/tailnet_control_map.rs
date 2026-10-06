//! The map message framing on arbitrary bytes split at arbitrary points: the payload bytes handed out never exceed the declared lengths.
#![no_main]
use libfuzzer_sys::fuzz_target;
use tdongle_tailnet_control::map::{MapEvent, MapFramer};

fuzz_target!(|data: &[u8]| {
    let Some((&sel, bytes)) = data.split_first() else { return };
    let mut f = MapFramer::new(1 << 20);
    let (mut declared, mut seen) = (0u64, 0u64);
    for chunk in bytes.chunks(1 + sel as usize % 53) {
        let mut rest = chunk;
        loop {
            match f.push(rest) {
                Err(_) => return,
                Ok((n, ev)) => {
                    rest = &rest[n..];
                    match ev {
                        Some(MapEvent::Start { len }) => {
                            declared = len as u64;
                            seen = 0;
                        }
                        Some(MapEvent::Json(j)) => {
                            seen += j.len() as u64;
                            assert!(seen <= declared);
                        }
                        Some(MapEvent::End) => assert_eq!(seen, declared),
                        None if n == 0 => break,
                        None => {}
                    }
                }
            }
        }
    }
});
