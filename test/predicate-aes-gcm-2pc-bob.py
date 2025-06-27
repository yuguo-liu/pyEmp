import sys
sys.path.append("../")
from build import pyEmp
import time
import random
import string
import json

def generate_hex_string(length, seed=None):
    if seed is not None:
        random.seed(seed)
    hex_chars = string.hexdigits.lower()[:16]
    return ''.join(random.choice(hex_chars) for _ in range(length))

if __name__=='__main__':
    party, port = 2, 12345
    print("I'm Bob!")

    exp_data = {}
    
    for block_length in [16, 32, 64, 128]:
        exp_data[f"block-{block_length}"] = {
            "online": 0.0,
            "offline": 0.0
        }
        print(f"{block_length}", "====" * 10)

        bob_m           = generate_hex_string(block_length * 32)
        bob_key_share   = generate_hex_string(32)
        bob_iv_share    = generate_hex_string(24)

        alice_m         = "0" * 32 * block_length
        alice_auth_data = "0" * 20
        alice_key_share = "0"
        alice_iv_share  = "0"
        r_com           = "0"
        commitment      = "0"
        
        len_c_i = len(bob_m) * 4
        len_a_i = len(alice_auth_data) * 4

        host = "127.0.0.1"

        s_time = time.time()
        aesgcm = pyEmp.EmpNaiveAesGcmPredicateEnc(party, host, port, len_c_i, len_a_i, False)
        aesgcm.offline_computation()
        offline_time = time.time() - s_time
        print(f"offline duration: {offline_time * 1000}ms")
        exp_data[f"block-{block_length}"]["offline_time"] = offline_time * 1000

        s_time = time.time()
        c = aesgcm.online_computation(bob_m, alice_auth_data, bob_key_share, bob_iv_share, commitment, r_com)
        online_time = time.time() - s_time
        print(f"online duration: {online_time * 1000}ms")
        exp_data[f"block-{block_length}"]["online_time"] = online_time * 1000

        print(f"correction   :  0x{c[:1]}")
        print(f"get plaintext:  0x{c[1:1+len(bob_m)]}")
        print(f"get tag      :  0x{c[-32:]}")
    
    with open("./comm_data/predicate-aes-gcm.json", "w") as j:
        json.dump(exp_data, j, indent=4)
