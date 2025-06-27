import string
import sys
sys.path.append("../")
from build import pyEmp
import time
import random

def generate_hex_string(length, seed=None):
    if seed is not None:
        random.seed(seed)
    hex_chars = string.hexdigits.lower()[:16]
    return ''.join(random.choice(hex_chars) for _ in range(length))

if __name__=='__main__':
    party, port = 1, 12345
    print("I'm Alice!")

    for block_length in [16, 32, 64, 128]:
        print(f"{block_length}", "====" * 10)

        bob_m         = generate_hex_string(block_length * 32, seed=123)
        bob_key_share = "0"
        bob_iv_share  = "0"

        alice_auth_data = generate_hex_string(20, seed=123)
        alice_key_share = generate_hex_string(32, seed=123)
        alice_iv_share  = generate_hex_string(24, seed=123)
        
        len_c_i = len(bob_m) * 4
        len_a_i = len(alice_auth_data) * 4

        host = "127.0.0.1"

        s_time = time.time()
        aesgcm = pyEmp.EmpNaiveAesGcmEnc(party, host, port, len_c_i, len_a_i, False)
        aesgcm.offline_computation()
        print(f"offline duration: {(time.time() - s_time) * 1000}ms")

        s_time = time.time()
        c = aesgcm.online_computation(bob_m, alice_auth_data, alice_key_share, alice_iv_share)
        print(f"online duration: {(time.time() - s_time) * 1000}ms")

        print(f"get cipher 0x{c[:-32]}")
        print(f"get tag    0x{c[-32:]}")
    
    
