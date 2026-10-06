//! Host harness. `gen` records the fixtures (Noise IK reply + record, a real rustls TLS 1.3 transcript, the CA);
//! `measure` runs the SAME model code under a counting allocator (64-bit host: pointer-bearing types are larger than on xtensa).
mod gen;
mod measure;

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("gen") => gen::run(),
        Some("measure") => measure::run(),
        _ => eprintln!("usage: s4-host gen|measure"),
    }
}
