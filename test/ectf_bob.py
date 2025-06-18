import sys
sys.path.append("../")
from build import pyEmp

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

    ectf = pyEmp.EmpECtF(party, host, port, False)
    ectf.offline_computation()
    res = ectf.online_computation(str_x + str_y)

    print(res)

