#ifndef _UTILS_H_
#define _UTILS_H_

#include <iostream>
#include <random>
#include <string>
#include <sstream>
#include <iomanip>
#include <time.h>
#include <emp-tool/emp-tool.h>
#include <emp-ag2pc/emp-ag2pc.h>

using namespace std;

void random_bool_sequence(bool* seq, const int len) {
    random_device rd;
    for (int i = 0; i < len; i++) {
        seq[i] = rd() % 2 == 0;
    }
}

void bignum_to_blocks(BIGNUM *bn, block *block1, block *block2) {
    int len = BN_num_bytes(bn);
    
    if (len > 32) {
        fprintf(stderr, "BIGNUM should be within 256bits\n");
        return;
    }

    unsigned char *bn_bytes = (unsigned char*) OPENSSL_malloc(len);
    if (bn_bytes == NULL) {
        fprintf(stderr, "memory allocation failed\n");
        return;
    }

    BN_bn2bin(bn, bn_bytes);

    *block1 = _mm_setzero_si128();
    *block2 = _mm_setzero_si128();

    // Copy bytes into the blocks
    if (len <= 16) {
        for (int i = 0; i < len; i++) {
            ((unsigned char*)&(*block2))[15 - i] = bn_bytes[i];
        }
    } else {
        for (int i = (32 - len); i < 16; i++) {
            ((unsigned char*)&(*block1))[15 - i] = bn_bytes[i - (32 - len)];
        }
        for (int i = 16; i < 32; i++) {
            ((unsigned char*)&(*block2))[31 - i] = bn_bytes[i - (32 - len)];
        }
    }

    OPENSSL_free(bn_bytes);
}

void blocks_to_bignum(block block1, block block2, BIGNUM **bn) {
    unsigned char bn_bytes[32] = {0};  // Initialize to zero to handle padding

    unsigned char *block1_bytes = (unsigned char*)&block1;
    for (int i = 0; i < 16; i++) {
        bn_bytes[i] = block1_bytes[15 - i];
    }

    unsigned char *block2_bytes = (unsigned char*)&block2;
    for (int i = 0; i < 16; i++) {
        bn_bytes[16 + i] = block2_bytes[15 - i];
    }

    *bn = BN_bin2bn(bn_bytes, 32, NULL);  // Create BIGNUM from stripped bytes
}

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

void hex_string_to_unsigned_char_array(const std::string& hexStr, unsigned char* byteArray) {
    if (hexStr.length() != 64) {
        std::cerr << "Error: The input hex string must be 64 characters long!" << std::endl;
        return;
    }

    for (size_t i = 0; i < 32; ++i) {
        std::stringstream ss;
        ss << std::hex << hexStr.substr(i * 2, 2);
        int byte;
        ss >> byte;
        byteArray[i] = static_cast<unsigned char>(byte);
    }
}
#endif