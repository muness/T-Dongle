fn main() {
    embuild::build::CfgArgs::output_propagated("ESP_IDF").expect("esp-idf cfg");
    embuild::build::LinkArgs::output_propagated("ESP_IDF").expect("esp-idf link args");
}
