//! The other direction of the power-loss model: ESP-IDF's own C++ NVS (compiled for the host, `tools/idf_c_check`) is the *writer*, cut at
//! every Nth unit of programming while it runs the same sequence the firmware's C code runs (`wifi_meta`, then `wifi_profiles`, mode, a
//! multi-page blob, a string, an erase), and this crate's mount, reader and engine must take what the cut leaves: the old or the new
//! value of every key, no other key touched, and a partition that keeps working. That is the case of a device that loses power while the
//! v0.3.x C firmware is saving and then boots the Rust one.
mod common;

use common::harness::*;
use common::*;
use std::io::Read;
use tdongle_nvs_write::{SimFlash, Store};

const SCRIPT: &str = "blob tn_settings wifi_meta 516 7
blob tn_settings wifi_profiles 784 8
u8 tn_settings mode 0
blob tailnet directory 9000 3
str tn_settings members carol
erase tn_settings display
blob tn_settings wifi_profiles 784 9
";

fn steps() -> Vec<Step> {
    vec![
        Box::new(|s: &mut St| s.nvs().set_blob("tn_settings", "wifi_meta", &pattern(516, 7))),
        Box::new(|s: &mut St| s.nvs().set_blob("tn_settings", "wifi_profiles", &pattern(784, 8))),
        Box::new(|s: &mut St| s.nvs().set_u8("tn_settings", "mode", 0)),
        Box::new(|s: &mut St| s.nvs().set_blob("tailnet", "directory", &pattern(9000, 3))),
        Box::new(|s: &mut St| s.nvs().set_str("tn_settings", "members", "carol")),
        Box::new(|s: &mut St| match s.nvs().erase_key("tn_settings", "display") {
            Err(tdongle_nvs_write::Error::NotFound) => Ok(()),
            r => r,
        }),
        Box::new(|s: &mut St| s.nvs().set_blob("tn_settings", "wifi_profiles", &pattern(784, 9))),
    ]
}

fn c_binary() -> Option<std::path::PathBuf> {
    // `idf_c_run` builds the binary on first use; run it on nothing to get it built, then find it next to the export directory
    idf_c_run(&[vec![0xff; 3 * 4096]], false)?;
    Some(std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("idf_c_check"))
}

fn sweep_c_writer(name: &str, base: Vec<u8>, script: &str, steps: Vec<Step>, pair: Option<(&'static str, &'static str, &'static str)>, stride: u64) {
    let Some(bin) = c_binary() else { return };
    let dir = export_dir().join(format!("c_writer_{name}"));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("base.bin"), &base).unwrap();
    std::fs::write(dir.join("script.txt"), script).unwrap();
    let out = std::process::Command::new(bin)
        .arg("--crash-sweep")
        .arg(dir.join("base.bin"))
        .arg(dir.join("script.txt"))
        .arg(dir.join("images.bin"))
        .arg(stride.to_string())
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stdout));
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let cuts: Vec<(u64, usize, bool)> = text
        .lines()
        .filter_map(|l| l.strip_prefix("CUT "))
        .map(|l| {
            let f: Vec<&str> = l.split(' ').collect();
            (f[0].parse().unwrap(), f[1].parse().unwrap(), f[2] == "1")
        })
        .collect();
    assert!(cuts.len() > 100, "{text}");
    let sc = Scenario { name: "c_writer", base: base.clone(), steps, pair, rerun: true, churn: 0 };
    let run = prepare(&sc);
    let mut f = std::io::BufReader::new(std::fs::File::open(dir.join("images.bin")).unwrap());
    let mut died_count = 0;
    for (n, k, died) in &cuts {
        let mut img = vec![0u8; SIZE as usize];
        f.read_exact(&mut img).unwrap();
        let what = format!("{name}: ESP-IDF writer cut at {n}, in step {k}");
        let k = if *died { *k } else { sc.steps.len() - 1 };
        let repaired = run.check_image(&img, k, &what);
        // the partition keeps working: the whole sequence again reaches the final state
        let mut again = Store::mount(SimFlash::from_image(repaired), SIZE).unwrap();
        for (i, s) in sc.steps.iter().enumerate() {
            s(&mut again).unwrap_or_else(|e| panic!("{what}: step {i}: {e:?}"));
        }
        assert_same(&format!("{what}: after running the sequence again"), &dump(again.nvs()), run.states.last().unwrap());
        died_count += usize::from(*died);
    }
    eprintln!("{name}: ESP-IDF as writer: {} crash images ({died_count} cut mid-write) taken by this crate's mount", cuts.len());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn esp_idf_cut_while_writing_then_this_crates_mount() {
    let mut base_store = board();
    // the C script creates namespaces itself, but start from a base that has them all so the sweep covers value writes
    base_store.nvs().set_blob("tailnet", "directory", &pattern(9000, 1)).unwrap();
    let base = base_store.nvs().flash().data.clone();
    sweep_c_writer("main", base, SCRIPT, steps(), Some(("tn_settings", "wifi_meta", "wifi_profiles")), env_u64("NVS_C_WRITER_STRIDE", 11));
}

/// ESP-IDF's own page compaction (`FREEING` pages, half-copied target pages) cut at every Nth unit, and this crate's mount finishing it.
#[test]
fn esp_idf_cut_while_compacting_then_this_crates_mount() {
    let probe: Step = Box::new(|s: &mut St| s.save_profiles(&list(5, 77).0, &list(5, 77).1));
    let base = base_before_compaction(board(), |t| save(1 + (t as usize % 8), t), probe);
    let script = "blob tn_settings wifi_profiles 784 77\nblob tn_settings wifi_meta 516 78\n";
    let steps: Vec<Step> = vec![
        Box::new(|s: &mut St| s.nvs().set_blob("tn_settings", "wifi_profiles", &pattern(784, 77))),
        Box::new(|s: &mut St| s.nvs().set_blob("tn_settings", "wifi_meta", &pattern(516, 78))),
    ];
    sweep_c_writer("compaction", base, script, steps, None, env_u64("NVS_C_WRITER_STRIDE", 3));
}
