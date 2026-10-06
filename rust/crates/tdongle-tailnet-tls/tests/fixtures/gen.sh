#!/bin/bash
# Regenerates the DER fixtures of tdongle-tailnet-tls (mirrors alternative/tailnet/tests/derp_pki.py with ABSOLUTE validity so the
# fixtures are deterministic in time; the tests use NOW = 2026-10-06T00:00:00Z). Needs openssl >= 3.4 (x509 -not_before).
# Shape of the real DERP chain: leaf(P-256) <- YE2(P-384) <- Root YE(P-384) <- ISRG Root X2(P-384); X2 is also presented as a
# cross-certificate signed by ISRG Root X1 (RSA). NOT generated: derpkey.der and real_derp1_{0,1,2,3}.der, which are the certificates
# derp1.tailscale.com presented on 2026-10-06 (public data; the Ed25519 "derpkey" meta certificate has a 71 byte CN openssl refuses to make).
set -euo pipefail
O=${OPENSSL:-/opt/homebrew/opt/openssl@3/bin/openssl}
cd "$(dirname "$0")"; W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
NB_OK=20260901000000Z;  NA_OK=20360901000000Z     # valid at the test clock
NB_OLD=20260801000000Z; NA_OLD=20260901000000Z    # expired before it
NB_NEW=20261101000000Z; NA_NEW=20261201000000Z    # not yet valid
SERIAL=100
key() { case $2 in p256) $O genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out $W/$1.key 2>/dev/null;;
        p384) $O genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out $W/$1.key 2>/dev/null;;
        rsa) $O genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out $W/$1.key 2>/dev/null;; esac; }
# cert NAME CN KEYNAME ISSUER(or self) KIND [nb na sans md]
cert() {
  local name=$1 cn=$2 k=$3 iss=$4 kind=$5 nb=${6:-$NB_OK} na=${7:-$NA_OK} sans=${8:-} md=${9:-sha384}
  SERIAL=$((SERIAL+1))
  { echo "[ext]"; case $kind in
      ca) echo "basicConstraints=critical,CA:TRUE"; echo "keyUsage=critical,keyCertSign,cRLSign";;
      leaf) echo "basicConstraints=critical,CA:FALSE"; echo "keyUsage=critical,digitalSignature"; echo "extendedKeyUsage=serverAuth,clientAuth";;
      leafnoeku) echo "basicConstraints=critical,CA:FALSE"; echo "keyUsage=critical,digitalSignature"; echo "extendedKeyUsage=clientAuth";;
      noca) echo "basicConstraints=critical,CA:FALSE"; echo "keyUsage=critical,digitalSignature";;
    esac
    if [ -n "$sans" ]; then echo "subjectAltName=$sans"; fi; } > $W/$name.ext
  $O req -new -key $W/$k.key -subj "/CN=$cn" -out $W/$name.csr
  if [ "$iss" = self ]; then
    $O x509 -req -in $W/$name.csr -signkey $W/$k.key -$md -not_before $nb -not_after $na -set_serial $SERIAL -extfile $W/$name.ext -extensions ext -outform DER -out $name.der 2>/dev/null
  else
    $O x509 -req -in $W/$name.csr -CA $W/$iss.pem -CAkey $W/$iss.key -$md -not_before $nb -not_after $na -set_serial $SERIAL -extfile $W/$name.ext -extensions ext -outform DER -out $name.der 2>/dev/null
  fi
  $O x509 -inform DER -in $name.der -out $W/$name.pem
  if [ ! -f $W/$name.key ]; then cp $W/$k.key $W/$name.key; fi
}
key x1 rsa; key x2 p384; key ye p384; key ye2 p384; key leafk p256; key rogue p384; key rogue_i p384
key fake_x2 p384; key fake_ye p384; key fake_ye2 p384; key pin p256; key pin2 p256
cert x1 "Test ISRG Root X1" x1 self ca
cert x2 "Test ISRG Root X2" x2 self ca
cert x2_cross "Test ISRG Root X2" x2 x1 ca                       # same subject + key as x2, issued by X1 (RSA signature)
cert x2_cross_old "Test ISRG Root X2" x2 x1 ca $NB_OLD $NA_OLD
cert x2_cross_new "Test ISRG Root X2" x2 x1 ca $NB_NEW $NA_NEW
cert ye "Test Root YE" ye x2 ca
cert ye_expired "Test Root YE" ye x2 ca $NB_OLD $NA_OLD
cert ye2 "Test YE2" ye2 ye ca
cert ye2_old "Test YE2" ye2 ye ca $NB_OLD $NA_OLD
cert ye2_noca "Test YE2" ye2 ye noca
cert leaf_ok "derp1.test.example" leafk ye2 leaf $NB_OK $NA_OK "DNS:derp1.test.example"
cert leaf_sha256sig "derp1.test.example" leafk ye2 leaf $NB_OK $NA_OK "DNS:derp1.test.example" sha256
cert leaf_other "other.example" leafk ye2 leaf $NB_OK $NA_OK "DNS:other.example"
cert leaf_wild "wild.example" leafk ye2 leaf $NB_OK $NA_OK "DNS:*.wild.example"
cert leaf_ip "192.0.2.7" leafk ye2 leaf $NB_OK $NA_OK "IP:192.0.2.7"
cert leaf_ip6 "ip6" leafk ye2 leaf $NB_OK $NA_OK "IP:2001:db8::7"
cert leaf_expired "derp1.test.example" leafk ye2 leaf $NB_OLD $NA_OLD "DNS:derp1.test.example"
cert leaf_future "derp1.test.example" leafk ye2 leaf $NB_NEW $NA_NEW "DNS:derp1.test.example"
cert leaf_cn_only "derp1.test.example" leafk ye2 leaf                                  # CommonName only, no SAN
cert leaf_noeku "derp1.test.example" leafk ye2 leafnoeku $NB_OK $NA_OK "DNS:derp1.test.example"
cert leaf_front "front.example" leafk ye2 leaf $NB_OK $NA_OK "DNS:derp1.test.example"
cert leaf_is_ca "derp1.test.example" leafk ye2 ca $NB_OK $NA_OK "DNS:derp1.test.example"
cert leaf_under_noca "derp1.test.example" leafk ye2_noca leaf $NB_OK $NA_OK "DNS:derp1.test.example"
cert rogue_ye "Test Root YE" rogue self ca
cert rogue_ye2 "Test YE2" rogue_i rogue_ye ca
cert leaf_rogue "derp1.test.example" leafk rogue_ye2 leaf $NB_OK $NA_OK "DNS:derp1.test.example"
cert fake_x2 "Test ISRG Root X2" fake_x2 self ca                  # same subject DN as X2, DIFFERENT key
cert fake_ye "Test Root YE" fake_ye fake_x2 ca
cert fake_ye2 "Test YE2" fake_ye2 fake_ye ca
cert leaf_fake "derp1.test.example" leafk fake_ye2 leaf $NB_OK $NA_OK "DNS:derp1.test.example"
cert renamed_x2 "Test ISRG Root X2 Renamed" x2 self ca           # X2's key under ANOTHER subject
cert renamed_ye "Test Root YE" ye renamed_x2 ca
cert pin "pin.example" pin self leaf $NB_OK $NA_OK "DNS:pin.example,IP:127.0.0.1"
cert pin_other "pin.example" pin2 self leaf $NB_OK $NA_OK "DNS:pin.example,IP:127.0.0.1"
cert pin_expired "pin.example" pin self leaf $NB_OLD $NA_OLD "DNS:pin.example"
cert pin_wrong_name "pin.example" pin self leaf $NB_OK $NA_OK "DNS:wrong-name.example"
for k in leafk pin pin2; do $O pkcs8 -topk8 -nocrypt -in $W/$k.key -outform DER -out key_$k.der; done

# RSA known-answer fixtures for src/rsa.rs: message "tdongle rsa kat", RSAPublicKey DER, and signatures made by openssl.
printf 'tdongle rsa kat' > rsa_msg.bin
for bits in 2048 4096; do
  $O genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:$bits -out $W/rsa$bits.key 2>/dev/null
  $O rsa -in $W/rsa$bits.key -RSAPublicKey_out -outform DER -out rsa${bits}_pub.der 2>/dev/null
  $O pkeyutl -sign -inkey $W/rsa$bits.key -rawin -in rsa_msg.bin -digest sha256 -out rsa${bits}_pkcs1_sha256.sig
  $O pkeyutl -sign -inkey $W/rsa$bits.key -rawin -in rsa_msg.bin -digest sha384 -out rsa${bits}_pkcs1_sha384.sig
  for d in sha256 sha384; do
    $O pkeyutl -sign -inkey $W/rsa$bits.key -rawin -in rsa_msg.bin -digest $d -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:digest -pkeyopt rsa_mgf1_md:$d -out rsa${bits}_pss_$d.sig
  done
done
