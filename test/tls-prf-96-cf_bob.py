import sys
sys.path.append("../")
from build import pyEmp
import time

if __name__=='__main__':
    party, port = 2, 12345
    print("I'm Bob!")
    seed = 0xc4b4ebe8578f4ca02a8d833d2cde604ba8896ab61ae7fdd274a8df438c903f56
    m = 0x29260e341e76c7c05fe77ab4a607fc54359fb953f7db9299e5b3746a5351b232685cfae47cc361351b4d19a547537b16

    str_seed = hex(seed)[2:]
    str_seed = "0" * (64 - len(str_seed)) + str_seed

    str_m = hex(m)[2:]
    str_m = "0" * (96 - len(str_m)) + str_m

    host = "127.0.0.1"

    s_time = time.time()
    tls_prf_96 = pyEmp.EmpTlsPrfCFSF(party, host, port, "client finished", False)
    tls_prf_96.offline_computation()
    print(f"offline duration: {(time.time() - s_time) * 1000}ms")

    input("Press the key to continue...")

    s_time = time.time()
    res = tls_prf_96.online_computation(str_seed, str_m)
    print(f"online duration: {(time.time() - s_time) * 1000}ms")

    print(f"0x{res}")