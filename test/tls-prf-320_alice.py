import sys
sys.path.append("../")
from build import pyEmp
import time

if __name__=='__main__':
    party, port = 1, 12345
    print("I'm Alice!")
    s = 0xd04e53b410ecc2290ed94f6d1ea1a8cd5480cce19cb8d5e3444f574e47524401
    c = 0x40a0ef21998d7adf64589c7eaf9a37eb5300c17528b4be7c9e598d52c31f741a
    m = 0x1ac36c8db61892449eef287673d5e3e00e7db8920922d30c6eb3076887d8ffda6a2a8136f19c4ed5a00e4bb18c279547

    str_s = hex(s)[2:]
    str_s = "0" * (64 - len(str_s)) + str_s

    str_c = hex(c)[2:]
    str_c = "0" * (64 - len(str_c)) + str_c

    str_m = hex(m)[2:]
    str_m = "0" * (96 - len(str_m)) + str_m

    host = "127.0.0.1"

    s_time = time.time()
    tls_prf_320 = pyEmp.EmpTlsPrf320(party, host, port, False)
    tls_prf_320.offline_computation()
    print(f"offline duration: {(time.time() - s_time) * 1000}ms")

    input("Press the key to continue...")

    s_time = time.time()
    res = tls_prf_320.online_computation(str_s, str_c, str_m)
    print(f"online duration: {(time.time() - s_time) * 1000}ms")

    print(f"0x{res}")