from build import pyEmp

if __name__ == '__main__':
    eagc1 = pyEmp.EmpAg2pcGarbledCircuit("sha-256.txt", 1, "127.0.0.1", 12345, False)
    eagc1.offline_computation()
    out = eagc1.online_computation("fedc8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010")
    print(out)