#!/usr/bin/env python3
"""Test PKI for the DERP TLS verification tests. Writes PEM files into argv[1]
(relative validity: "now" is the time of generation)."""
import datetime, hashlib, ipaddress, pathlib, subprocess, sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

out = pathlib.Path(sys.argv[1]).resolve(); out.mkdir(parents=True, exist_ok=True)
now = datetime.datetime.now(datetime.timezone.utc)
day = datetime.timedelta(days=1)

def name(cn): return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
def pem(o): return o.public_bytes(serialization.Encoding.PEM)
def key_pem(k):
    return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())

def make(cn, issuer=None, issuer_key=None, sans=(), ca=False, before=-2*day, after=30*day, cn_only=False):
    key = ec.generate_private_key(ec.SECP256R1())
    b = (x509.CertificateBuilder().subject_name(name(cn)).issuer_name(issuer.subject if issuer else name(cn))
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now + before).not_valid_after(now + after)
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if ca:
        b = b.add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), critical=True)
    else:
        b = b.add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
        b = b.add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    if sans:
        names = [x509.IPAddress(ipaddress.ip_address(s[3:])) if s.startswith("ip:") else x509.DNSName(s) for s in sans]
        b = b.add_extension(x509.SubjectAlternativeName(names), critical=False)
    cert = b.sign(issuer_key or key, hashes.SHA256())
    return cert, key

def save(label, cert, key=None, chain=()):
    (out / f"{label}.pem").write_bytes(pem(cert) + b"".join(pem(c) for c in chain))
    if key: (out / f"{label}.key").write_bytes(key_pem(key))
    (out / f"{label}.sha256").write_text(hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest())

root, root_key = make("Test Root", ca=True, after=3650*day); save("root", root, root_key)
inter, inter_key = make("Test Intermediate", root, root_key, ca=True, after=3650*day); save("inter", inter, inter_key)
rogue, rogue_key = make("Rogue Root", ca=True, after=3650*day); save("rogue", rogue, rogue_key)

def leaf(label, *sans, issuer=(inter, inter_key), chain=(inter,), **kw):
    c, k = make(sans[0] if sans else "leaf", issuer[0], issuer[1], sans=sans, **kw); save(label, c, k, chain)

leaf("ok", "derp1.test.example")
leaf("other", "other.example")
leaf("wild", "*.wild.example")
leaf("expired", "derp1.test.example", before=-60*day, after=-30*day)
leaf("future", "derp1.test.example", before=30*day, after=60*day)
leaf("rogue_signed", "derp1.test.example", issuer=(rogue, rogue_key), chain=(rogue,))
leaf("ip", "ip:192.0.2.7")
leaf("front", "derp1.test.example")                        # served for a different SNI (CertName)
leaf("direct", "derp1.test.example", chain=())             # signed by the intermediate, which is NOT sent
# CommonName only, no subjectAltName: Go refuses, mbedTLS alone would accept.
c, k = make("derp1.test.example", inter, inter_key); save("cn_only", c, k, (inter,))
# Self-signed servers for the sha256-raw pin.
for label, kw in (("pin", {}), ("pin_other", {}), ("pin_expired", dict(before=-60*day, after=-30*day))):
    c, k = make("pin.example", sans=("pin.example", "ip:127.0.0.1"), **kw); save(label, c, k)
c, k = make("pin.example", sans=("wrong-name.example",)); save("pin_wrong_name", c, k)
# A second certificate presented next to the pinned one must fail (Tailscale: "unexpected multiple certs").
pin_c = x509.load_pem_x509_certificate((out / "pin.pem").read_bytes())
(out / "pin_plus_extra.pem").write_bytes(pem(pin_c) + pem(inter))
(out / "pin_plus_extra.key").write_bytes((out / "pin.key").read_bytes())

# Certificate bundle in the ESP-IDF format, trusting only the test root.
gen = pathlib.Path(sys.argv[2])
for label, files in (("bundle_root", ["root.pem"]), ("bundle_rogue", ["rogue.pem"])):
    subprocess.run([sys.executable, str(gen), "--input", *[str(out / f) for f in files], "-q"], cwd=out, check=True)
    (out / "x509_crt_bundle").rename(out / label)
print("PKI written to", out)
