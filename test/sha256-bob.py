import sys
sys.path.append("../")
from build import pyEmp

if __name__ == '__main__':
    eagc1 = pyEmp.EmpAg2pcGarbledCircuit("sha-256.txt", 2, "127.0.0.1", 12345, False)
    print("initialized the circuit")
    eagc1.offline_computation()
    print("offline computation finished")
    out = eagc1.online_computation("fedc8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010")
    print("online computation finished")
    print(out)