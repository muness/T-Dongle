// idf_c_check: mount NVS images with ESP-IDF's own C++ storage engine (components/nvs_flash/src, compiled unchanged) and dump what it reads.
//
//   idf_c_check [--churn] [--out DIR] IMAGE.bin...
//
// For every image: `MOUNT <esp_err>` (what nvs_flash_init would get, including every repair IDF's mount makes), then one row per key IDF
// resolves (`namespace key type length hex`, the format of tests/common and tools/verify_with_idf.py), then, with --churn, IDF writes 60
// blobs of 1000 bytes and erases them (several page compactions) and the rows are printed again as `AFTER_CHURN`. With --out the image
// IDF's mount left is written to DIR/<name>. Writes are NOR writes (bits only clear); a write that would set a bit is reported as
// `VIOLATION`. Reads and writes of the partition go through the abstract nvs::Partition, exactly where esp_partition_* sits on a device.
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <functional>
#include <list>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <type_traits>
#include <vector>
#define private public
#define protected public
#include "nvs_storage.hpp"
#undef private
#undef protected

extern "C" uint32_t esp_rom_crc32_le(uint32_t crc, uint8_t const *buf, uint32_t len)
{
    uint32_t c = ~crc;
    for (uint32_t i = 0; i < len; i++) {
        c ^= buf[i];
        for (int k = 0; k < 8; k++) c = (c & 1) ? (c >> 1) ^ 0xEDB88320u : c >> 1;
    }
    return ~c;
}

struct MemPartition : public nvs::Partition {
    std::vector<uint8_t> img;
    int violations = 0;
    // Power-loss injection: one unit per byte programmed, 4096 per sector erased; when `budget` runs out the operation is applied as far
    // as it was paid for (a prefix) and fails, and so does everything after it.
    int64_t budget = -1;
    int64_t spent = 0;
    bool dead = false;
    const char *get_partition_name() override { return "nvs"; }
    esp_err_t read_raw(size_t off, void *dst, size_t n) override { return rd(off, dst, n); }
    esp_err_t read(size_t off, void *dst, size_t n) override { return rd(off, dst, n); }
    esp_err_t write_raw(size_t off, const void *src, size_t n) override { return wr(off, src, n); }
    esp_err_t write(size_t off, const void *src, size_t n) override { return wr(off, src, n); }
    esp_err_t erase_range(size_t off, size_t n) override {
        if (dead) return ESP_FAIL;
        if (off + n > img.size() || off % 4096 || n % 4096) return ESP_ERR_INVALID_ARG;
        size_t paid = n;
        if (budget >= 0 && (int64_t)n > budget - spent) paid = budget - spent > 0 ? budget - spent : 0;
        memset(&img[off], 0xff, paid);
        spent += paid;
        if (paid < n) { dead = true; return ESP_FAIL; }
        return ESP_OK;
    }
    uint32_t get_address() override { return 0; }
    uint32_t get_size() override { return img.size(); }
    bool get_readonly() override { return false; }
    esp_err_t rd(size_t off, void *dst, size_t n) {
        if (off + n > img.size()) return ESP_ERR_INVALID_SIZE;
        memcpy(dst, &img[off], n);
        return ESP_OK;
    }
    esp_err_t wr(size_t off, const void *src, size_t n) {
        if (dead) return ESP_FAIL;
        if (off + n > img.size() || off % 4 || n % 4) return ESP_ERR_INVALID_SIZE;
        const uint8_t *s = (const uint8_t *)src;
        size_t paid = n;
        if (budget >= 0 && (int64_t)n > budget - spent) paid = budget - spent > 0 ? budget - spent : 0;
        for (size_t i = 0; i < paid; i++) {
            if (s[i] & ~img[off + i]) violations++;
            img[off + i] &= s[i];
        }
        spent += paid;
        if (paid < n) { dead = true; return ESP_FAIL; }
        return ESP_OK;
    }
};

using namespace nvs;

static const char *type_name(ItemType t, size_t &width)
{
    width = 0;
    switch (t) {
    case ItemType::U8: width = 1; return "uint8_t";
    case ItemType::I8: width = 1; return "int8_t";
    case ItemType::U16: width = 2; return "uint16_t";
    case ItemType::I16: width = 2; return "int16_t";
    case ItemType::U32: width = 4; return "uint32_t";
    case ItemType::I32: width = 4; return "int32_t";
    case ItemType::U64: width = 8; return "uint64_t";
    case ItemType::I64: width = 8; return "int64_t";
    case ItemType::SZ: return "string";
    case ItemType::BLOB: case ItemType::BLOB_IDX: return "blob";
    default: return "?";
    }
}

static void dump(Storage &st, const char *skip_ns)
{
    // namespaces
    std::map<int, std::string> names;
    std::set<std::pair<int, std::string>> keys;
    for (auto p = st.mPageManager.begin(); p != st.mPageManager.end(); ++p) {
        size_t idx = 0;
        Item item;
        while (p->findItem(Page::NS_ANY, ItemType::ANY, nullptr, idx, item) == ESP_OK) {
            idx += item.span;
            char key[16];
            item.getKey(key, sizeof(key));
            if (item.nsIndex == 0) names[item.data[0]] = key;
            else if (item.datatype != ItemType::BLOB_DATA) keys.insert({item.nsIndex, key});
        }
    }
    std::vector<std::string> rows;
    for (auto &k : keys) {
        ItemType t;
        if (st.findKey(k.first, k.second.c_str(), &t) != ESP_OK) { printf("ROWERR %d %s findKey\n", k.first, k.second.c_str()); continue; }
        size_t w;
        const char *tn = type_name(t, w);
        std::vector<uint8_t> buf(8);
        size_t len = w;
        esp_err_t e = ESP_OK;
        if (t == ItemType::SZ || t == ItemType::BLOB || t == ItemType::BLOB_IDX) {
            ItemType rt = t == ItemType::BLOB_IDX ? ItemType::BLOB : t;
            e = st.getItemDataSize(k.first, rt, k.second.c_str(), len);
            if (e == ESP_OK) { buf.resize(len + 1); e = st.readItem(k.first, rt, k.second.c_str(), buf.data(), len); }
        } else {
            e = st.readItem(k.first, t, k.second.c_str(), buf.data(), w);
        }
        std::string ns = names.count(k.first) ? names[k.first] : "?";
        if (skip_ns && ns == skip_ns) continue;
        if (e != ESP_OK) { rows.push_back(ns + "\t" + k.second + "\tREADERR\t" + std::to_string(e)); continue; }
        char hex[3];
        std::string h;
        for (size_t i = 0; i < len; i++) { snprintf(hex, 3, "%02x", buf[i]); h += hex; }
        rows.push_back(ns + "\t" + k.second + "\t" + tn + "\t" + std::to_string(len) + "\t" + h);
    }
    std::sort(rows.begin(), rows.end());
    for (auto &r : rows) printf("%s\n", r.c_str());
}

// ---- --crash-sweep: ESP-IDF as the *writer* ----------------------------------------------------------------------------------------------
// idf_c_check --crash-sweep BASE.bin SCRIPT OUT.bin STRIDE
//
// SCRIPT lines: `blob NS KEY LEN SEED` (nvs_set_blob of the pattern below), `u8 NS KEY V`, `str NS KEY TEXT`, `erase NS KEY`. The script runs on the
// mounted BASE through ESP-IDF's Storage with the flash failing after N units, for N = 0, STRIDE, 2*STRIDE ... up to the total cost, and the image
// each cut leaves is appended to OUT.bin. Prints `STEPS c1 c2 ...` (cumulative cost after each step), then `CUT n step died` per image.
static std::vector<uint8_t> pattern(size_t n, uint32_t seed)
{
    uint32_t x = seed * 2654435761u + 1;
    std::vector<uint8_t> v(n);
    for (auto &b : v) { x = (x * 1103515245u + 12345u) & 0x7fffffffu; b = (x >> 16) & 0xff; }
    return v;
}

struct Step { std::string op, ns, key, arg; size_t len = 0; uint32_t seed = 0; };

static esp_err_t run_step(Storage &st, const Step &s)
{
    uint8_t ns;
    esp_err_t e = st.createOrOpenNamespace(s.ns.c_str(), true, ns);
    if (e != ESP_OK) return e;
    if (s.op == "blob") { auto d = pattern(s.len, s.seed); return st.writeItem(ns, ItemType::BLOB, s.key.c_str(), d.data(), d.size()); }
    if (s.op == "u8") { uint8_t v = (uint8_t)atoi(s.arg.c_str()); return st.writeItem(ns, ItemType::U8, s.key.c_str(), &v, 1); }
    if (s.op == "str") return st.writeItem(ns, ItemType::SZ, s.key.c_str(), s.arg.c_str(), s.arg.size() + 1);
    if (s.op == "erase") { e = st.eraseItem(ns, ItemType::ANY, s.key.c_str()); return e == ESP_ERR_NVS_NOT_FOUND ? ESP_OK : e; }
    return ESP_ERR_INVALID_ARG;
}

static int crash_sweep(const char *base, const char *script, const char *outpath, int stride)
{
    std::vector<uint8_t> baseimg;
    { FILE *f = fopen(base, "rb"); if (!f) return 2; uint8_t t[4096]; size_t n; while ((n = fread(t, 1, sizeof t, f)) > 0) baseimg.insert(baseimg.end(), t, t + n); fclose(f); }
    std::vector<Step> steps;
    { std::ifstream in(script); std::string line;
      while (std::getline(in, line)) { std::istringstream ls(line); Step s; ls >> s.op >> s.ns >> s.key; if (s.op.empty()) continue;
        if (s.op == "blob") ls >> s.len >> s.seed; else if (s.op == "u8") ls >> s.arg; else if (s.op == "str") { std::getline(ls >> std::ws, s.arg); }
        steps.push_back(s); } }
    auto run = [&](int64_t budget, std::vector<int64_t> *ends, MemPartition &part, int *step_at, bool *died) -> bool {
        part.img = baseimg; part.budget = -1; part.spent = 0; part.dead = false;
        Storage st(&part);
        if (st.init(0, part.img.size() / 4096) != ESP_OK) return false;
        part.budget = budget; part.spent = 0;
        int k = 0;
        for (auto &s : steps) {
            esp_err_t e = run_step(st, s);
            if (e != ESP_OK) break;
            if (ends) ends->push_back(part.spent);
            k++;
        }
        *step_at = k; *died = part.dead;
        return true;
    };
    MemPartition part; std::vector<int64_t> ends; int k; bool died;
    if (!run(-1, &ends, part, &k, &died) || k != (int)steps.size()) { printf("SWEEPERR full run failed at step %d\n", k); return 3; }
    printf("STEPS"); for (auto e : ends) printf(" %lld", (long long)e); printf("\n");
    FILE *out = fopen(outpath, "wb");
    int64_t total = ends.back();
    for (int64_t n = 0; n <= total; n += stride) {
        MemPartition p;
        if (!run(n, nullptr, p, &k, &died)) { printf("SWEEPERR mount\n"); return 3; }
        fwrite(p.img.data(), 1, p.img.size(), out);
        printf("CUT %lld %d %d\n", (long long)n, k, died ? 1 : 0);
    }
    fclose(out);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 6 && !strcmp(argv[1], "--crash-sweep")) return crash_sweep(argv[2], argv[3], argv[4], atoi(argv[5]));
    bool churn = false;
    const char *out = nullptr;
    std::vector<const char *> files;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--churn")) churn = true;
        else if (!strcmp(argv[i], "--out") && i + 1 < argc) out = argv[++i];
        else files.push_back(argv[i]);
    }
    for (const char *f : files) {
        printf("== %s\n", f);
        FILE *fp = fopen(f, "rb");
        if (!fp) { printf("MOUNT NOFILE\n"); continue; }
        MemPartition part;
        uint8_t tmp[4096];
        size_t n;
        while ((n = fread(tmp, 1, sizeof tmp, fp)) > 0) part.img.insert(part.img.end(), tmp, tmp + n);
        fclose(fp);
        Storage st(&part);
        esp_err_t e = st.init(0, part.img.size() / 4096);
        printf("MOUNT %d\n", (int)e);
        if (e == ESP_OK) {
            dump(st, nullptr);
            if (churn) {
                uint8_t ns;
                esp_err_t c = st.createOrOpenNamespace("scratch", true, ns);
                std::vector<uint8_t> data(1000);
                for (int i = 0; i < 60 && c == ESP_OK; i++) {
                    for (auto &b : data) b = (uint8_t)(i * 7 + (&b - &data[0]));
                    c = st.writeItem(ns, ItemType::BLOB, "churn", data.data(), data.size());
                }
                if (c == ESP_OK) c = st.eraseItem(ns, ItemType::ANY, "churn");
                printf("CHURN %d\n", (int)c);
                printf("AFTER_CHURN\n");
                dump(st, "scratch");
            }
        }
        if (part.violations) printf("VIOLATION %d\n", part.violations);
        if (out) {
            std::string path = std::string(out) + "/" + (strrchr(f, '/') ? strrchr(f, '/') + 1 : f);
            FILE *o = fopen(path.c_str(), "wb");
            if (o) { fwrite(part.img.data(), 1, part.img.size(), o); fclose(o); }
        }
    }
    return 0;
}
