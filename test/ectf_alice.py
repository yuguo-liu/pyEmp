import sys
sys.path.append("../")
from build import pyEmp
import time

if __name__=='__main__':
    party, port = 1, 12345
    print("I'm Alice!")
    x = 0xaa80468d22f31ee672768b587526fbd88fb7fb3d304adec816d27fa7b34dd60d
    y = 0xbf276ab3b55cd976216973797d0a11f1328038dfd5834a357ada46abe359a794

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