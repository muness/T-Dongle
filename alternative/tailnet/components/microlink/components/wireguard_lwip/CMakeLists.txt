set(wg_crypto_srcs
    "src/crypto/refc/blake2s.c"
    "src/crypto/refc/chacha20.c"
    "src/crypto/refc/chacha20poly1305.c"
    "src/crypto/refc/poly1305-donna.c"
    "src/crypto/refc/x25519.c"
    # Self-test + cycle benchmark behind the `crypto bench` console command (a few hundred
    # bytes, always built; the command is what makes the cost visible on the board).
    "src/crypto/wg_crypto_bench.c"
)
# Original (pre-optimisation) implementation, only for the A/B column of `crypto bench`.
if(CONFIG_WG_CRYPTO_BENCH_BASELINE)
    list(APPEND wg_crypto_srcs "src/crypto/legacy/wg_crypto_legacy.c")
endif()

idf_component_register(
    SRCS
        "src/wireguard.c"
        "src/wireguardif.c"
        "src/crypto.c"
        "src/wireguard-platform-esp32.c"
        ${wg_crypto_srcs}
    INCLUDE_DIRS
        "src"
        "src/crypto"
        "src/crypto/refc"
    REQUIRES
        lwip
        esp_timer
)

target_compile_definitions(${COMPONENT_LIB} PRIVATE
    WIREGUARD_CRYPTO_REFC=1
)

# Disable stringop-overread warning for x25519.c (false positive in GCC array bounds check)
set_source_files_properties(
    src/crypto/refc/x25519.c
    PROPERTIES COMPILE_FLAGS "-Wno-stringop-overread"
)
