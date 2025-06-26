import sys
sys.path.append("../")
from build import pyEmp
import time

if __name__=='__main__':
    party, port = 2, 12345
    print("I'm Bob!")
    
    bob_m           = "8e6414c404b7726c038baf352f86cef9"
    bob_tag         = "4b59db0dca2bb7bb01efe13f4695b566"
    bob_key_share   = "a368091b9dcc0048ba7d3f288630209a"
    bob_iv_share    = "aefb80590000000000000000"

    alice_auth_data = "0" * 26
    alice_key_share = "0"
    alice_iv_share  = "0"
    
    len_c_i = len(bob_m) * 4
    len_a_i = len(alice_auth_data) * 4

    host = "127.0.0.1"

    s_time = time.time()
    aesgcm = pyEmp.EmpNaiveAesGcmDec(party, host, port, len_c_i, len_a_i, False)
    aesgcm.offline_computation()
    print(f"offline duration: {(time.time() - s_time) * 1000}ms")

    s_time = time.time()
    m = aesgcm.online_computation(bob_m, alice_auth_data, bob_key_share, bob_iv_share, bob_tag)
    print(f"online duration: {(time.time() - s_time) * 1000}ms")

    print(f"correction   :  0x{m[:1]}")
    print(f"get plaintext:  0x{m[1:1+len(bob_m)]}")