import sys
sys.path.append("../")
from build import pyEmp
import time

if __name__=='__main__':
    party, port = 2, 12345
    print("I'm Bob!")
    s = 0xd37ea8b78aafcf19ebf4194fcb43f9a521db20c42445325b444f574e47524401
    c = 0xe105c540dd7273d6ed89775ed58e0d67d99edac40241dad3eccda240e3291649
    m = 0x12187d1f90b4a8cfdacf8848e2cb24074c885989bc302275db3988edf62e9bff

    str_s = hex(s)[2:]
    str_s = "0" * (64 - len(str_s)) + str_s

    str_c = hex(c)[2:]
    str_c = "0" * (64 - len(str_c)) + str_c

    str_m = hex(m)[2:]
    str_m = "0" * (64 - len(str_m)) + str_m

    host = "127.0.0.1"

    s_time = time.time()
    tls_prf_384 = pyEmp.EmpTlsPrf384(party, host, port, False)
    tls_prf_384.offline_computation()
    print(f"offline duration: {(time.time() - s_time) * 1000}ms")

    s_time = time.time()
    res = tls_prf_384.online_computation(str_s, str_c, str_m)
    print(f"online duration: {(time.time() - s_time) * 1000}ms")

    print(f"0x{res}")