"""Regenerate independent Apple-SRP vectors using cocagne/pysrp's _pysrp.py.

Pass a directory containing srp.py (upstream _pysrp.py) and six.py. These
references are not vendored or used at runtime. Output goes to stdout.
"""
import hashlib
import json
import sys

sys.path.insert(0, sys.argv[1])
import srp

srp.rfc5054_enable()
srp.no_username_in_x()
vectors = []
for protocol in ["s2k", "s2k_fo"]:
    username, password = "fixture@example.invalid", "test-password-only"
    salt = bytes.fromhex("00112233445566778899aabbccddeeff")
    secret = bytes.fromhex("112233445566778899aabbccddeeff00112233445566778899aabbccddeeff0011")
    password_hash = hashlib.sha256(password.encode()).digest()
    if protocol == "s2k_fo":
        password_hash = password_hash.hex().encode()
    derived = hashlib.pbkdf2_hmac("sha256", password_hash, salt, 1000, 32)
    client = srp.User(username, derived, hash_alg=srp.SHA256, ng_type=srp.NG_2048,
                      bytes_a=secret.rjust(256, b"\0"))
    _, A = client.start_authentication()
    # A fixed valid server public value suffices to independently check client
    # proof derivation, including its RFC5054 padding and Apple password KDF.
    B = pow(2, 123456789, client.N).to_bytes(256, "big")
    M = client.process_challenge(salt, B)
    vectors.append(dict(protocol=protocol, username=username, password=password,
                        salt=salt.hex(), a=secret.hex(), B=B.hex(), A=A.hex(),
                        M1=M.hex(), M2=client.H_AMK.hex(), K=client.K.hex()))
print(json.dumps(vectors, indent=2))
