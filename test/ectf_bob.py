import sys
sys.path.append("../")
from build import pyEmp
import time

if __name__=='__main__':
    party, port = 2, 12345
    print("I'm Bob!")
    x = 0x59667a44af6f56b7a0774523c6d07664df548705a38016968be03c22a6ef6844
    y = 0x0965ebee806a48a7870bd3107bcd93be78196f2241203ac4c78cfc98ce3605c4

    str_x = hex(x)[2:]
    str_x = "0" * (64 - len(str_x)) + str_x

    str_y = hex(y)[2:]
    str_y = "0" * (64 - len(str_y)) + str_y

    host = "127.0.0.1"

    s_time = time.time()
    ectf = pyEmp.EmpECtF(party, host, port, False)
    ectf.offline_computation()
    print(f"offline duration: {(time.time() - s_time) * 1000}ms")

    input("Press the key to continue...")

    s_time = time.time()
    res = ectf.online_computation(str_x + str_y)
    print(f"online duration: {(time.time() - s_time) * 1000}ms")

    print(res)