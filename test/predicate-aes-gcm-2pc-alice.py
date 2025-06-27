import sys
sys.path.append("../")
from build import pyEmp
import time
import random
import string

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

        bob_m         = "0" * 32 * block_length
        bob_key_share = "0"
        bob_iv_share  = "0"

        alice_m         = generate_hex_string(block_length * 32)
        alice_auth_data = generate_hex_string(20)
        alice_key_share = generate_hex_string(32)
        alice_iv_share  = generate_hex_string(24)
        r_com           = "8dd1485d13f3728ec81f2fab68c304b3"
        commitment      = "592e332c40056a34e250f4a0ba579980db85c24ede7ba66b09b67ccee100a65d"
        
        len_c_i = len(bob_m) * 4
        len_a_i = len(alice_auth_data) * 4

        host = "127.0.0.1"

        s_time = time.time()
        aesgcm = pyEmp.EmpNaiveAesGcmPredicateEnc(party, host, port, len_c_i, len_a_i, False)
        aesgcm.offline_computation()
        print(f"offline duration: {(time.time() - s_time) * 1000}ms")

        s_time = time.time()
        c = aesgcm.online_computation(alice_m, alice_auth_data, alice_key_share, alice_iv_share, commitment, r_com)
        print(f"online duration: {(time.time() - s_time) * 1000}ms")

        print(f"correction   :  0x{c[:1]}")
        print(f"get plaintext:  0x{c[1:1+len(bob_m)]}")
        print(f"get tag      :  0x{c[-32:]}")
