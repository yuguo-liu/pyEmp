#include <emp-tool/emp-tool.h>
#include <emp-ag2pc/emp-ag2pc.h>
using namespace std;
using namespace emp;

const string circuit_file_location = string("/usr/local/include/emp-tool/circuits/files/bristol_format/");

char bin_to_hex_char(const string& bin) {
    if (bin == "0000") return '0';
    if (bin == "0001") return '1';
    if (bin == "0010") return '2';
    if (bin == "0011") return '3';
    if (bin == "0100") return '4';
    if (bin == "0101") return '5';
    if (bin == "0110") return '6';
    if (bin == "0111") return '7';
    if (bin == "1000") return '8';
    if (bin == "1001") return '9';
    if (bin == "1010") return 'a';
    if (bin == "1011") return 'b';
    if (bin == "1100") return 'c';
    if (bin == "1101") return 'd';
    if (bin == "1110") return 'e';
    if (bin == "1111") return 'f';
    return '0'; 
}

string binary_to_hex(const string& bin) {
    string hex;
    int length = bin.length();

    if (length % 4 != 0) {
        int padding = 4 - (length % 4);
        string padded_bin = string(padding, '0') + bin;
        length = padded_bin.length();

        for (int i = 0; i < length; i += 4) {
            hex += bin_to_hex_char(padded_bin.substr(i, 4));
        }
    } else {
        for (int i = 0; i < length; i += 4) {
            hex += bin_to_hex_char(bin.substr(i, 4));
        }
    }

    return hex;
}

const char* hex_char_to_bin(char c) {
	switch(toupper(c)) {
		case '0': return "0000";
		case '1': return "0001";
		case '2': return "0010";
		case '3': return "0011";
		case '4': return "0100";
		case '5': return "0101";
		case '6': return "0110";
		case '7': return "0111";
		case '8': return "1000";
		case '9': return "1001";
		case 'A': return "1010";
		case 'B': return "1011";
		case 'C': return "1100";
		case 'D': return "1101";
		case 'E': return "1110";
		case 'F': return "1111";
		default: return "0";
	}
}

string hex_to_binary(string hex) {
	string bin;
	for(unsigned i = 0; i != hex.length(); ++i)
		bin += hex_char_to_bin(hex[i]);
	return bin;
}

class EmpAg2pcGarbledCircuit {
private:
    BristolFormat* cf;
    NetIO* io;
    C2PC<NetIO>* twopc;
    int party;
    bool is_online;
    bool debug;
public:
    EmpAg2pcGarbledCircuit(string circuit_file_name, int _party, const char *IP, int port, bool _debug = false) {
        string cfn = circuit_file_location + circuit_file_name;
        cout << cfn << endl;
        cf = new BristolFormat(cfn.c_str());
        party = _party;
        io = new NetIO(party == ALICE ? nullptr : IP, port);

        auto t1 = emp::clock_start();
        twopc = new C2PC<NetIO>(io, party, cf);
        io->flush();
        cout << "one time:\t" << party << "\t" << emp::time_from(t1) <<endl;
        
        is_online = false;
        debug = _debug;
    }

    void offline_computation() {
        auto t1 = emp::clock_start();
        twopc->function_independent();
        io->flush();
        cout << "inde:\t" << party << "\t" << emp::time_from(t1) << endl;

        t1 = emp::clock_start();
        twopc->function_dependent();
        io->flush();
        cout << "dep:\t" << party << "\t" << emp::time_from(t1) << endl;
        is_online = true;
    }

    string online_computation(string hin = "", string check_output = "") {
        if (!is_online) {
            cout << "do the offline computation first" << endl;
            offline_computation();
        }
        bool *in; 
        bool *out;
        in = new bool[cf->n1 + cf->n2];
        out = new bool[cf->n3];
        if (hin.size() > 0) {
            string bin = hex_to_binary(hin);
            for (int i=0; i < cf->n1 + cf->n2; ++i) {
                if (bin[i] == '0') 
                    in[i] = false;
                else if (bin[i] == '1') 
                    in[i] = true;
                else {
                    cout << "problem: " << bin[i] << endl;
                    exit(1);
                }
            }
        } else {
            memset(in, false, cf->n1 + cf->n2);
        }

        memset(out, false, cf->n3);
        auto t1 = emp::clock_start();
        twopc->online(in, out, true);
        cout << "online:\t" << party << "\t" << emp::time_from(t1) << endl;
        
        if (debug) {
            cout << "actual output: " << endl;
            for (int i=0; i < cf->n3; ++i)
                cout << out[i];
            cout << endl;
        }

        string res = "";
        for(int i = 0; i < cf->n3; ++i){
            res += (out[i] ? "1" : "0");
        }

        if(check_output.size() > 0) {
            cout << (res == hex_to_binary(check_output) ? "GOOD!" : "BAD!") << endl;
        }

        delete[] in;
        delete[] out;

        return binary_to_hex(res);
    }
};