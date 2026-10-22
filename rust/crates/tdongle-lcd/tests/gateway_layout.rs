use tdongle_lcd::{
    LCD_ROWS, ROW_BYTES,
    view::{LAYOUT_ROWS, compose_text_rows},
};

#[test]
fn long_ssid_does_not_overwrite_gateway_status_or_secret() {
    let view = compose_text_rows(
        ["Wireless AP ready", "a very long network name beyond the available row", "WiFi -58 dBm", "Tailnets 3/3 ready", "Internet not checked"],
        false,
    );
    assert_eq!(view.layout, LAYOUT_ROWS);
    assert_eq!(&view.text[2 * ROW_BYTES..2 * ROW_BYTES + 12], b"WiFi -58 dBm");
    assert_eq!(&view.text[4 * ROW_BYTES..4 * ROW_BYTES + 20], b"Internet not checked");
    for row in view.text.chunks_exact(ROW_BYTES).take(LCD_ROWS) {
        assert_eq!(row[ROW_BYTES - 1], 0);
    }
}

#[test]
fn setup_password_url_and_expiry_have_separate_rows() {
    let view = compose_text_rows(["Temporary setup", "TDongle-C5-AABBCC", "ABCDEF23456789GH", "http://192.168.4.1", "Expires in 600s"], false);
    for (index, expected) in [(2, b"ABCDEF23456789GH".as_slice()), (3, b"http://192.168.4.1"), (4, b"Expires in 600s")] {
        assert_eq!(&view.text[index * ROW_BYTES..index * ROW_BYTES + expected.len()], expected);
    }
}

#[test]
fn truncation_preserves_character_boundary() {
    let view = compose_text_rows(["é".repeat(30).as_str(), "unchanged", "", "", ""], false);
    let row = &view.text[..ROW_BYTES];
    let end = row.iter().position(|b| *b == 0).unwrap();
    assert!(core::str::from_utf8(&row[..end]).is_ok());
    assert_eq!(&view.text[ROW_BYTES..ROW_BYTES + 9], b"unchanged");
}
