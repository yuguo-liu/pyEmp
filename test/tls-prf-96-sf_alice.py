import sys
sys.path.append("../")
from build import pyEmp
import time

if __name__=='__main__':
    party, port = 1, 12345
    print("I'm Alice!")
    seed = 0xc4b4ebe8578f4ca02a8d833d2cde604ba8896ab61ae7fdd274a8df438c903f56
    m = 0xbce43e9894393a897121bab60d3581b4bf36738dde8fa202554bbb16931d7897cec17bb36c3519dd827f7fb4f0962af0

    str_seed = hex(seed)[2:]
    str_seed = "0" * (64 - len(str_seed)) + str_seed

    str_m = hex(m)[2:]
    str_m = "0" * (96 - len(str_m)) + str_m

    host = "127.0.0.1"

    s_time = time.time()
    tls_prf_96 = pyEmp.EmpTlsPrfCFSF(party, host, port, "server finished", False)
    tls_prf_96.offline_computation()
    print(f"offline duration: {(time.time() - s_time) * 1000}ms")

    input("Press the key to continue...")

    s_time = time.time()
    res = tls_prf_96.online_computation(str_seed, str_m)
    print(f"online duration: {(time.time() - s_time) * 1000}ms")

    print(f"0x{res}")
