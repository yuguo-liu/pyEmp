import sys
sys.path.append("../")
from build import pyEmp
import time

if __name__=='__main__':
    party, port = 1, 12345
    print("I'm Alice!")
    
    bob_m         = "0" * 32
    bob_tag       = "0"
    bob_key_share = "0"
    bob_iv_share  = "0"

    alice_auth_data = "00000000000000001603030010"
    alice_key_share = "292a82fb6128f1aeda978c96053c7629"
    alice_iv_share  = "000000000000000000000000"
    
    len_c_i = len(bob_m) * 4
    len_a_i = len(alice_auth_data) * 4

    host = "127.0.0.1"

    s_time = time.time()
    aesgcm = pyEmp.EmpNaiveAesGcmDec(party, host, port, len_c_i, len_a_i, False)
    aesgcm.offline_computation()
    print(f"offline duration: {(time.time() - s_time) * 1000}ms")

    s_time = time.time()
    m = aesgcm.online_computation(bob_m, alice_auth_data, alice_key_share, alice_iv_share, bob_tag)
    print(f"online duration: {(time.time() - s_time) * 1000}ms")

    print(f"correction   :  0x{m[:1]}")
    print(f"get plaintext:  0x{m[1:1+len(bob_m)]}")