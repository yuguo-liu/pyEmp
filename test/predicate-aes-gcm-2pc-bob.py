import sys
sys.path.append("../")
from build import pyEmp
import time

if __name__=='__main__':
    party, port = 2, 12345
    print("I'm Bob!")
    
    bob_m           = "c848e6aaf66451755937f73814dab1c9ac26bf1a9926001a37d5eb22a8695817736f85e6ef54b2c37e5923a6d8134b2b51f59ac31da2ed7e8bbbb70474b2c21815a276ab193b5fc3477db1c3e740d96bc5658b5fb3f041fbfcd609c79989660f66aba44631d57b43b279f9324de87a82a9c25baf5ba871d76882a0db4b409f0a2458453af765ef5a416d26da4a4cdb1ecdde02301eefbdbab81c04e347fcafbd"
    bob_key_share   = "102030405060708090a0b0c0d0e0f000"
    bob_iv_share    = "102030405060708090a0b0c0"

    alice_m         = "0" * 320
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
    print(f"offline duration: {(time.time() - s_time) * 1000}ms")

    s_time = time.time()
    c = aesgcm.online_computation(bob_m, alice_auth_data, bob_key_share, bob_iv_share, commitment, r_com)
    print(f"online duration: {(time.time() - s_time) * 1000}ms")

    print(f"correction   :  0x{c[:1]}")
    print(f"get plaintext:  0x{c[1:1+len(bob_m)]}")
    print(f"get tag      :  0x{c[-32:]}")