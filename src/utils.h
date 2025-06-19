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

// Function to convert hex string to binary string
string hex_to_bin(const string &hex) {
    string bin;
    for (char c : hex)
    {
        int value = stoi(string(1, c), nullptr, 16);
        bin += bitset<4>(value).to_string(); // Convert each hex digit to 4-bit binary
    }
    return bin;
}

// Function to convert binary string to hex string
string bin_to_hex(const string &bin) {
    stringstream hex;
    for (size_t i = 0; i < bin.size(); i += 4)
    {
        int value = stoi(bin.substr(i, 4), nullptr, 2);
        hex << std::hex << value; // Convert 4-bit binary to hex digit
    }
    return hex.str();
}

// Function to reverse the binary representation of a hex string
string reverse_hex_binary(const string &hex)
{
    string binary = hex_to_bin(hex); // Convert hex to binary
    reverse(binary.begin(), binary.end()); // Reverse binary string
    return bin_to_hex(binary); // Convert reversed binary back to hex
}

// Function to convert an integer to a 16-character hexadecimal string
string int_to_hex_16(int value)
{
    stringstream stream;
    stream << std::setfill('0') << std::setw(16) << std::hex << std::uppercase << (unsigned int)value;
    return stream.str();
}

/**
 * Pads a hexadecimal string with zeros so that its length is a multiple of 32.
 * If the string length is already a multiple of 32, no padding is applied.
 * 
 * @param hex_str The input hexadecimal string to be padded.
 * @return The padded hexadecimal string.
 */
string pad_hex_string(const string& hex_str) {
    // Calculate the length of the input string
    size_t length = hex_str.length();
    
    // Calculate the remainder when the length is divided by 32
    size_t remainder = length % 32;
    
    // If the remainder is not zero, calculate the number of zeros needed for padding
    if (remainder != 0) {
        size_t padding_length = 32 - remainder;
        
        // Create a string with the required number of zeros
        string padding(padding_length, '0');
        
        // Append the padding to the original string
        return hex_str + padding;
    }
    
    // If the length is already a multiple of 32, return the original string
    return hex_str;
}

string padding_mask(int length_plaintext) {
    /**
     * generating padding mask for aes-gcm in the case that 128 is not a factor of length plaintext
     * generates a 128-bit hex that the first m bits are 1, and the last 128 - m bits are 0
     */
    int m = length_plaintext % 128;

    uint64_t high = 0;
    uint64_t low = 0;

    if (m > 0) {
        if (m < 64) {
            high = ((1ULL << m) - 1) << (64 - m);
        } else {
            high = ~0ULL;
            low = ((1ULL << (m - 64)) - 1) << (128 - m);
        }
    } else {
        high = ~0ULL;
        low = ~0ULL;
    }

    uint64_t result_high = high;
    uint64_t result_low = low;

    stringstream ss;
    ss << hex << setw(16) << setfill('0') << result_high;
    ss << setw(16) << setfill('0') << result_low;

    return ss.str();
}

string sha256_padding(const string &hex_str) {
    int original_length = hex_str.length();
    int additional_length = 112 - (original_length % 128);
    if (additional_length <= 0) additional_length += 128;

    size_t padded_length = original_length + additional_length + 16;

    // Add the '1' bit (0x80 in hex, i.e., 8 bits) to the end of the hex string
    string padded_str = hex_str + "80";

    // Add '0's to make the string length 64-byte aligned minus the 64-bit length
    while (padded_str.length() < padded_length - 16) {
        padded_str += "00";
    }

    // Append the length of the original string (in bits) in hex (64-bit length)
    stringstream length_stream;
    length_stream << setfill('0') << setw(16) << hex << original_length * 4;
    padded_str += length_stream.str();

    return padded_str;
}

string zero_padding(const string &hex_str, size_t target_length) {
    string filled_str = hex_str;
    while (filled_str.length() < target_length) {
        filled_str += "00";
    }
    return filled_str;
}

int get_padding_length(const string &hex_str) {
	int original_length = hex_str.length();
    int additional_length = 112 - (original_length % 128);
    if (additional_length <= 0) additional_length += 128;
	return original_length + additional_length;
}

string utf8_to_hex(const std::string &utf8_str) {
    stringstream hex_stream;

    for (unsigned char c : utf8_str) {
        hex_stream << std::setw(2) << std::setfill('0') << std::hex << (int)c;
    }

    return hex_stream.str();
}
#endif