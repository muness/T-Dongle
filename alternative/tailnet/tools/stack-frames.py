#!/usr/bin/env python3
"""Print the stack frame size of functions in the linked ELF.

Hardware high-water marks only cover the paths a capture exercised. To reason
about the others, add up the frames along a real call chain: this prints each
function's `entry aN, <frame>` from the disassembly (exact per function; a call
graph recovered from a stripped-down disassembly is not, because indirect calls
and unnamed local functions cannot be resolved, so the chains are summed by
hand from the source). Each windowed-ABI call level may also spill 16 bytes of
registers.

usage: stack-frames.py build/app.elf [function ...]   (no names = the task and
       DERP/Noise/TLS/WireGuard chain functions used in microlink_internal.h)
"""
import re, subprocess, sys

DEFAULT = """ml_net_io_task ml_derp_tx_task ml_derp_connect derp_write_frame derp_read_exact verify_cb
ml_derp_tls_describe esp_crt_verify_callback mbedtls_ssl_handshake mbedtls_ssl_handshake_client_step
mbedtls_ssl_parse_certificate mbedtls_ssl_verify_certificate mbedtls_x509_crt_verify_restartable
mbedtls_pk_verify_ext rsa_verify_wrap mbedtls_rsa_rsassa_pkcs1_v15_verify mbedtls_rsa_public
mbedtls_ecdsa_verify_restartable mbedtls_ecp_muladd_restartable mbedtls_ssl_write_record
mbedtls_ssl_encrypt_buf mbedtls_ssl_decrypt_buf ml_coord_task do_map_exchange do_noise_handshake
ctrl_key_fetch key_tls_open esp_tls_conn_new_sync gateway_read_map ml_directory_commit
ml_netcheck_pick_best_derp ml_wg_mgr_task process_wg_packet derp_sender_admit directory_activate_idle
directory_reconcile add_peer wireguardif_network_rx wireguard_process_initiation_message
wireguard_process_handshake_response ml_x25519 nacl_box_beforenm blake2s_compress""".split()

def main():
    elf, names = sys.argv[1], sys.argv[2:] or DEFAULT
    out = subprocess.check_output(["xtensa-esp32s3-elf-objdump", "-d", "--no-show-raw-insn", elf], text=True)
    frames, cur = {}, None
    for line in out.splitlines():
        m = re.match(r"^[0-9a-f]+ <([^>]+)>:$", line)
        if m:
            cur = m.group(1)
            continue
        m = re.match(r"^\s*[0-9a-f]+:\s+entry\s+a1,\s*(0x[0-9a-f]+|\d+)", line)
        if m and cur and cur not in frames:
            frames[cur] = int(m.group(1), 0)
    for n in names:
        print(f"{n:48s}{frames.get(n, 'not found')}")

main()
