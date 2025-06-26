#ifndef _PYEMP_H_
#define _PYEMP_H_

#include <time.h>
#include <random>
#include <string>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <emp-tool/emp-tool.h>
#include <emp-ag2pc/emp-ag2pc.h>

#include "plaintext_sha256.h"
#include "utils.h"

using namespace std;
using namespace emp;

const string circuit_file_location = string("/usr/local/include/emp-tool/circuits/files/bristol_format/");

class EmpAg2pcGarbledCircuit {
private:
    BristolFormat* cf;
    NetIO* io;
    C2PC<NetIO>* twopc;
    int party;
    bool is_online;
    bool debug;

public:
    EmpAg2pcGarbledCircuit(string circuit_file_name, int _party, const char *IP, int port, bool _debug = false);
    void offline_computation();
    string online_computation(string hin = "", string check_output = "");
    NetIO* get_NetIO();
};

class EmpECtF{
private:
    EmpAg2pcGarbledCircuit *add_2_xor_circuit;
    int party;
    NetIO *io;
    IKNP<NetIO> *ot;
    const string cfn = "ECtF/add_2_xor_p256.txt";
    bool DEBUG;
    bool LOG;
    
    void mta(BIGNUM **share, IKNP<NetIO> *ot, int party, NetIO *io, BIGNUM **data, const int len_data, BIGNUM *P, BN_CTX *ctx);

public:
    EmpECtF(int _party, const char *IP, int port, bool _debug = false, bool _log = false);
    void offline_computation();
    string online_computation(string hin = "", string check_output = "");
};

class EmpTlsPrf384 {
private:
    EmpAg2pcGarbledCircuit *hmac1;
    EmpAg2pcGarbledCircuit *hmac2;
    EmpAg2pcGarbledCircuit *hmac3;
    EmpAg2pcGarbledCircuit *hmac4;
    EmpAg2pcGarbledCircuit *hmac5;
    const string iv_0 = "e6679056a175e6dd4ecf763c5caff2a5fe4a708a3116a0d9d59bc1f898b307da";
    const string hmac1_cfn = "KDF/sha256_i_2_share_msg_2_mask_1_state_o_2_share.txt";
    const string hmac2_cfn = "KDF/sha256_i_2_share_msg_1_state_o_hash_state.txt";
    const string hmac3_cfn = "KDF/sha256_i_2_share_state_1_msg_o_hash.txt";
    const string hmac4_cfn = "KDF/sha256_i_2_share_state_1_msg_o_hash.txt";
    const string hmac5_cfn = "KDF/sha256_i_2_share_state_2_full_msg_o_2_share_hash.txt";
    const string IPAD = "36";
    const string OPAD = "5c";
    bool DEBUG;
    int party;

public:
    EmpTlsPrf384(int _party, const char *IP, int port, bool _debug = false);
    void offline_computation();
    string online_computation(string rnd_s, string rnd_c, string share, string check_output = "");
};

class EmpTlsPrf320 {
private:
    EmpAg2pcGarbledCircuit *hmac1;
    EmpAg2pcGarbledCircuit *hmac2;
    EmpAg2pcGarbledCircuit *hmac3;
    EmpAg2pcGarbledCircuit *hmac4;
    EmpAg2pcGarbledCircuit *hmac5;
    const string iv_0 = "e6679056a175e6dd4ecf763c5caff2a5fe4a708a3116a0d9d59bc1f898b307da";
    const string hmac1_cfn = "KDF/sha256_i_2_share_msg_2_mask_1_state_o_2_share.txt";
    const string hmac2_cfn = "KDF/sha256_i_2_share_msg_1_state_o_hash_state.txt";
    const string hmac3_cfn = "KDF/sha256_i_2_share_state_1_msg_o_hash.txt";
    const string hmac4_cfn = "KDF/sha256_i_2_share_state_1_msg_o_hash.txt";
    const string hmac5_cfn = "KDF/sha256_i_2_share_state_2_full_msg_o_2_share_hash_1_key_hash_320.txt";
    const string IPAD = "36";
    const string OPAD = "5c";
    bool DEBUG;
    int party;

public:
    EmpTlsPrf320(int _party, const char *IP, int port, bool _debug = false);
    void offline_computation();
    string online_computation(string rnd_s, string rnd_c, string share, string check_output = "");
};

class EmpTlsPrfCFSF {
private:
    EmpAg2pcGarbledCircuit *hmac1;
    EmpAg2pcGarbledCircuit *hmac2;
    EmpAg2pcGarbledCircuit *hmac3;
    EmpAg2pcGarbledCircuit *hmac4;
    EmpAg2pcGarbledCircuit *hmac5;
    const string iv_0 = "e6679056a175e6dd4ecf763c5caff2a5fe4a708a3116a0d9d59bc1f898b307da";
    const string hmac1_cfn = "KDF/sha256_i_2_share_msg_2_mask_1_state_o_2_share.txt";
    const string hmac2_cfn = "KDF/sha256_i_2_share_msg_1_state_o_hash_state.txt";
    const string hmac3_cfn = "KDF/sha256_i_2_share_state_1_msg_o_hash.txt";
    const string hmac4_cfn = "KDF/sha256_i_2_share_state_1_msg_o_hash.txt";
    const string hmac5_cfn = "KDF/sha256_i_2_share_state_2_full_msg_o_2_share_96.txt";
    const string IPAD = "36";
    const string OPAD = "5c";
    bool DEBUG;
    int party;
    string msg;

public:
    EmpTlsPrfCFSF(int _party, const char *IP, int port, string msg, bool _debug = false);
    void offline_computation();
    string online_computation(string seed, string share, string check_output = "");
};

class EmpNaiveAesGcmEnc {
private:
    EmpAg2pcGarbledCircuit *aesgcm_circuit;
    int party;
    int len_c_i;
    int len_a_i;
    bool DEBUG;

public:
    EmpNaiveAesGcmEnc(int _party, const char *IP, int port, int _len_c, int _len_a, bool _debug = false);
    void offline_computation();
    string online_computation(string m, string ad, string key_share, string iv_share);
};

class EmpNaiveAesGcmDec {
private:
    EmpAg2pcGarbledCircuit *aesgcm_circuit;
    int party;
    int len_c_i;
    int len_a_i;
    bool DEBUG;

public:
    EmpNaiveAesGcmDec(int _party, const char *IP, int port, int _len_c, int _len_a, bool _debug = false);
    void offline_computation();
    string online_computation(string c, string ad, string key_share, string iv_share, string tag);
};

class EmpNaiveAesGcmPredicateEnc {
private:
    EmpAg2pcGarbledCircuit *pre_aesgcm_circuit;
    int party;
    int len_c_i;
    int len_a_i;
    bool DEBUG;

public:
    EmpNaiveAesGcmPredicateEnc(int _party, const char *IP, int port, int _len_c, int _len_a, bool _debug = false);
    void offline_computation();
    string online_computation(string m, string ad, string key_share, string iv_share, string commitment, string r_com);
};

EmpAg2pcGarbledCircuit::EmpAg2pcGarbledCircuit(string circuit_file_name, int _party, const char *IP, int port, bool _debug) {
    string cfn = circuit_file_location + circuit_file_name;
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

void EmpAg2pcGarbledCircuit::offline_computation() {
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

string EmpAg2pcGarbledCircuit::online_computation(string hin, string check_output) {
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

NetIO* EmpAg2pcGarbledCircuit::get_NetIO() {
    return io;
}

void EmpECtF::mta(BIGNUM **share, IKNP<NetIO> *ot, int party, NetIO *io, BIGNUM **data, const int len_data, BIGNUM *P, BN_CTX *ctx) {
    const int security_param = 128;
    int param = 256 + security_param;

    clock_t t_s, t_e;

    BIGNUM *_res = BN_new();
    BN_zero(_res);
    for (int i = 0; i < len_data; i++) {
        BIGNUM *datum = data[i];
        if (party == ALICE) {
            // step 1: random sample vector delta
            t_s = clock();
            BIGNUM *Delta[param];
            for (int i = 0; i < param; i++) {
                Delta[i] = BN_new();
                BN_rand_range(Delta[i], P);
                // cout << BN_bn2hex(Delta[i]) << endl;
            }
            t_e = clock();
            if (DEBUG) cout << party << ": step 1: random sample vector delta [" << (double) (t_e - t_s) / CLOCKS_PER_SEC * 1000 << "ms]" << endl;

            // step 2: generate Z_0 & Z_1
            t_s = clock();
            BIGNUM *Z_0[param];
            BIGNUM *Z_1[param];

            for (int i = 0; i < param; i++) {
                Z_0[i] = BN_new();
                Z_1[i] = BN_new();
                BN_mod_sub(Z_0[i], Delta[i], datum, P, ctx);
                BN_mod_add(Z_1[i], Delta[i], datum, P, ctx);
            }
            t_e = clock();
            if (DEBUG) cout << party << ": step 2: generate Z_0 & Z_1 [" << (double) (t_e - t_s) / CLOCKS_PER_SEC * 1000 << "ms]" << endl;

            // step 3: raise OTs and send the msgs
            t_s = clock();
            block Z_0_blocks[param * 2];
            block Z_1_blocks[param * 2];

            for (int i = 0; i < param; i++) {
                bignum_to_blocks(Z_0[i], &Z_0_blocks[i * 2], &Z_0_blocks[i * 2 + 1]);
                bignum_to_blocks(Z_1[i], &Z_1_blocks[i * 2], &Z_1_blocks[i * 2 + 1]);
            }

            t_e = clock();
            if (DEBUG) cout << party << ": step 3.1: pre-phase raise OTs and send the msgs [" << (double) (t_e - t_s) / CLOCKS_PER_SEC * 1000 << "ms]" << endl;

            // ot->send_rot(Z_0_blocks, Z_1_blocks, param * 2);
            for (int i = 0; i < param && LOG; i++) {
                cout << "alice: " << Z_0_blocks[i * 2] << " " << Z_0_blocks[i * 2 + 1] << endl;
                cout << "alice: " << Z_1_blocks[i * 2] << " " << Z_1_blocks[i * 2 + 1] << endl;
            }
            
            t_s = clock();
            ot->send(Z_0_blocks, Z_1_blocks, param * 2);
            t_e = clock();

            for (int i = 0; i < param && LOG; i++) {
                cout << "alice: " << BN_bn2hex(Z_0[i]) << " / " << BN_bn2hex(Z_1[i]) << endl;
            }

            if (DEBUG) cout << party << ": step 3.2: OT-phase raise OTs and send the msgs [" << (double) (t_e - t_s) / CLOCKS_PER_SEC * 1000 << "ms]" << endl;

            // step 4: recv V
            t_s = clock();
            block V_blocks[param * 2];
            io->recv_block(V_blocks, param * 2);

            BIGNUM *V[param];
            for (int i = 0; i < param; i++) {
                V[i] = BN_new();
                blocks_to_bignum(V_blocks[i * 2], V_blocks[i * 2 + 1], &V[i]);
            }
            t_e = clock();

            for (int i = 0; i < param && LOG; i++) {
                cout << "alice: " << BN_bn2hex(V[i]) << endl;
            }

            if (DEBUG) cout << party << ": step 4: recv V [" << (double) (t_e - t_s) / CLOCKS_PER_SEC * 1000 << "ms]" << endl;

            // step 5: calculate the share
            t_s = clock();
            BIGNUM *res = BN_new();
            BIGNUM *tmp = BN_new();
            BN_zero(res);
            for (int i = 0; i < param; i++) {
                BN_mod_mul(tmp, Delta[i], V[i], P, ctx);
                BN_mod_add(res, res, tmp, P, ctx);
            }
            t_e = clock();
            if (DEBUG) cout << party << ": step 5: calculate the share [" << (double) (t_e - t_s) / CLOCKS_PER_SEC * 1000 << "ms]" << endl;

            BN_mod_sub(_res, _res, res, P, ctx);
        } else {
            // step 1: randomly sample B and V[:param-1]
            if (DEBUG) cout << party << ": step 1: randomly sample B" << endl;
            bool B[param];
            random_bool_sequence(B, param);

            BIGNUM *V[param];
            BIGNUM *previous_V = BN_new();
            BN_zero(previous_V);
            
            for (int i = 0; i < param - 1; i++) {
                V[i] = BN_new();
                BN_rand_range(V[i], P);
            }

            // step 2: raise OTs and receive the msgs
            if (DEBUG) cout << party << ": step 2: raise OTs and receive the msgs" << endl;
            block Z_blocks[param * 2];
            bool B_ot[param * 2];

            for (int i = 0; i < param; i++) {
                B_ot[i * 2] = B[i];
                B_ot[i * 2 + 1] = B[i];
            }

            // ot->recv_rot(Z_blocks, B_ot, param * 2);
            t_s = clock();
            ot->recv(Z_blocks, B_ot, param * 2);
            t_e = clock();
            // cout << "ot time: " << (double) (t_e - t_s) / CLOCKS_PER_SEC << "s" << endl;

            // for (int i = 0; i < param; i++) {
            //     ot->recv(&Z_blocks[i*2], &B_ot[i*2], 2);
            // }

            for (int i = 0; i < param && LOG; i++) {
                cout << "bob: " << Z_blocks[i * 2] << " " << Z_blocks[i * 2 + 1] << endl;
            }

            BIGNUM *Z[param];
            for (int i = 0; i < param; i++) {
                Z[i] = BN_new();
                blocks_to_bignum(Z_blocks[i * 2], Z_blocks[i * 2 + 1], &Z[i]);
            }

            for (int i = 0; i < param && LOG; i++) {
                cout << "bob:   " << BN_bn2hex(Z[i]) << " / " << B[i] << endl;
            }

            // step 3: randomly sample V s.t. <V, t> = datum
            if (DEBUG) cout << party << ": step 3: randomly sample V s.t. <V, t> = datum" << endl;
            for (int i = 0; i < param - 1; i++) {
                if (!B[i]) {
                    BN_mod_sub(previous_V, previous_V, V[i], P, ctx);
                } else {
                    BN_mod_add(previous_V, previous_V, V[i], P, ctx);
                }
            }

            V[param - 1] = BN_new();
            if (!B[param - 1]) {
                BN_mod_sub(V[param - 1], previous_V, datum, P, ctx);
            } else {
                BN_mod_sub(V[param - 1], datum, previous_V, P, ctx);
            }

            // step 4: send V
            if (DEBUG) cout << party << ": step 4: send V" << endl;
            block V_blocks[param * 2];
            for (int i = 0; i < param; i++) {
                bignum_to_blocks(V[i], &V_blocks[i * 2], &V_blocks[i * 2 + 1]);
            }

            io->send_block(V_blocks, param * 2);

            for (int i = 0; i < param && LOG; i++) {
                cout << "bob:   " << BN_bn2hex(V[i]) << endl;
            }

            // step 5: calculate the share
            if (DEBUG) cout << party << ": step 5: calculate the share" << endl;
            BIGNUM *res = BN_new();
            BIGNUM *tmp = BN_new();
            BN_zero(res);
            for (int i = 0; i < param; i++) {
                BN_mod_mul(tmp, Z[i], V[i], P, ctx);
                BN_mod_add(res, res, tmp, P, ctx);
            }

            BN_mod_add(_res, _res, res, P, ctx);
        }
    }

    io->flush();
    *share = _res;
}

EmpECtF::EmpECtF(int _party, const char *IP, int port, bool _debug, bool _log) {
    // load the add to xor circuit
    add_2_xor_circuit = new EmpAg2pcGarbledCircuit(cfn, _party, IP, port, _debug);
    party = _party;
    io = add_2_xor_circuit->get_NetIO();
    ot = new IKNP<NetIO>(io, true);     // malicious ot
    DEBUG = _debug;
    LOG = _log;
}

void EmpECtF::offline_computation() {
    add_2_xor_circuit->offline_computation();
}

string EmpECtF::online_computation(string hin, string check_output) {
    clock_t start_t, end_t;
    unsigned char x_chars[32], y_chars[32];
    unsigned char p_chars[32] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    };
    
    string x_s = hin.substr(0, 64);
    string y_s = hin.substr(64, 64);
    if (DEBUG) cout << x_s << endl;
    if (DEBUG) cout << y_s << endl;

    if (x_s.length() != 64 || y_s.length() != 64) {
        cerr << "Parameter error: x, y of the point on p256 should be 256 bits" << endl;
        exit(2);
    }

    unsigned char x_c[32], y_c[32];
    hex_string_to_unsigned_char_array(x_s, x_c);
    hex_string_to_unsigned_char_array(y_s, y_c);
    
    for (int i = 0; i < 32; i++) {
        x_chars[i] = x_c[i];
        y_chars[i] = y_c[i];
    }

    // initialize the bignum
    BN_CTX *ctx = BN_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "Failed to create BN_CTX\n");
        exit(-1);
    }

    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    BIGNUM *p = BN_new();
    BIGNUM *zero = BN_new();

    BN_bin2bn(x_chars, sizeof(x_chars), x);
    BN_bin2bn(y_chars, sizeof(y_chars), y);
    BN_bin2bn(p_chars, sizeof(p_chars), p);
    BN_zero(zero);

    if (DEBUG) cout << party << "'s x: 0x" << BN_bn2hex(x) << endl;
    if (DEBUG) cout << party << "'s y: 0x" << BN_bn2hex(y) << endl;

    start_t = clock();
    /**
     * step 1: rho <-R- Z_p
     */
    BIGNUM *rho = BN_new();
    BN_rand_range(rho, p);

    /**
     * step 2: alpha = MtA(), Alice sends [-x,rho], bob sends [rho,x]
     */
    BIGNUM *mta_data[2], *minus_x = BN_new();
    mta_data[0] = BN_new();
    mta_data[1] = BN_new();
    BN_mod_sub(minus_x, zero, x, p, ctx);
    if (party == ALICE) {
        mta_data[0] = minus_x;
        mta_data[1] = rho;
    } else {
        mta_data[0] = rho;
        mta_data[1] = x;
    }

    BIGNUM *alpha = BN_new();
    mta(&alpha, ot, party, io, mta_data, 2, p, ctx);

    if (DEBUG) cout << party << "'s mta input 0: 0x" << BN_bn2hex(mta_data[0]) << endl;
    if (DEBUG) cout << party << "'s mta input 1: 0x" << BN_bn2hex(mta_data[1]) << endl;
    if (DEBUG) cout << party << "'s mta output : 0x" << BN_bn2hex(alpha) << endl;

    /**
     * step 3: theta = -x * rho + alpha / x * rho + alpha
     */
    BIGNUM *theta_my = BN_new();
    if (party == ALICE) {
        BN_mod_mul(theta_my, minus_x, rho, p, ctx);
    } else {
        BN_mod_mul(theta_my, x, rho, p, ctx);
    }
    BN_mod_add(theta_my, theta_my, alpha, p, ctx);

    /**
     * step 4: jointly compute theta = theta_1 + theta_2
     */
    BIGNUM *theta = BN_new();
    if (party == ALICE) {
        block theta_blocks[2];
        bignum_to_blocks(theta_my, &theta_blocks[0], &theta_blocks[1]);
        io->send_block(theta_blocks, 2);

        io->recv_block(theta_blocks, 2);
        blocks_to_bignum(theta_blocks[0], theta_blocks[1], &theta);
        BN_mod_add(theta, theta, theta_my, p, ctx);
    } else {
        block theta_blocks[2];
        io->recv_block(theta_blocks, 2);
        blocks_to_bignum(theta_blocks[0], theta_blocks[1], &theta);

        bignum_to_blocks(theta_my, &theta_blocks[0], &theta_blocks[1]);
        io->send_block(theta_blocks, 2);
        BN_mod_add(theta, theta, theta_my, p, ctx);
    }

    /**
     * step 5: eta = rho * theta^-1
     */
    BIGNUM *eta = BN_new();
    BIGNUM *theta_inverse = BN_new();

    BN_mod_inverse(theta_inverse, theta, p, ctx);
    BN_mod_mul(eta, rho, theta_inverse, p, ctx);

    /**
     * step 6: beta = MtA(), Alice sends [-y,eta], bob sends [eta,y]
     */
    BIGNUM *mta_2_data[2], *minus_y = BN_new();
    mta_2_data[0] = BN_new();
    mta_2_data[1] = BN_new();
    BN_mod_sub(minus_y, zero, y, p, ctx);
    if (party == ALICE) {
        mta_2_data[0] = minus_y;
        mta_2_data[1] = eta;
    } else {
        mta_2_data[0] = eta;
        mta_2_data[1] = y;
    }

    BIGNUM *beta = BN_new();
    mta(&beta, ot, party, io, mta_2_data, 2, p, ctx);

    if (DEBUG) cout << party << "'s mta input 0: 0x" << BN_bn2hex(mta_2_data[0]) << endl;
    if (DEBUG) cout << party << "'s mta input 1: 0x" << BN_bn2hex(mta_2_data[1]) << endl;
    if (DEBUG) cout << party << "'s mta output : 0x" << BN_bn2hex(beta) << endl;

    /**
     * step 7: lambda = -y * eta + beta / lambda = y * eta + beta
     */
    BIGNUM *lambda = BN_new();
    if (party == ALICE) {
        BN_mod_mul(lambda, minus_y, eta, p, ctx);
    } else {
        BN_mod_mul(lambda, y, eta, p, ctx);
    }
    BN_mod_add(lambda, lambda, beta, p, ctx);

    /**
     * step 8: gamma = MtA(), Alice sends [lambda], bob sends [lambda]
     */
    BIGNUM *gamma = BN_new();
    mta(&gamma, ot, party, io, &lambda, 1, p, ctx);

    if (DEBUG) cout << party << "'s mta output : 0x" << BN_bn2hex(gamma) << endl;

    /**
     * step 9: s = 2 * gamma + lambda^2 - x
     */
    BIGNUM *s = BN_new();
    BIGNUM *double_gamma = BN_new();
    BIGNUM *lambda_square = BN_new();
    BIGNUM *two = BN_new();

    unsigned char two_c[1] = {0x02};
    BN_bin2bn(two_c, 1, two);

    BN_mod_mul(double_gamma, gamma, two, p, ctx);
    BN_mod_mul(lambda_square, lambda, lambda, p, ctx);

    BN_mod_add(s, double_gamma, lambda_square, p, ctx);
    BN_mod_sub(s, s, x, p, ctx);
    end_t = clock();

    if (DEBUG) cout << party <<"'s ECtF output: 0x" << BN_bn2hex(s) << endl;
    if (DEBUG) cout << party << ": ECtF duration: [" << (double) (end_t - start_t) / CLOCKS_PER_SEC * 1000 << "ms]" << endl;
    
    string additive_share = BN_bn2hex(s);

    if (DEBUG) cout << party << ": get " << additive_share << endl;

    if (party == ALICE) {
        bool stop[2] = {false, false};
        io->send_bool(stop, 2);
        bool cont[2];
        io->recv_bool(cont, 2);
    } else {
        bool stop[2];
        io->recv_bool(stop, 2);
        bool cont[2] = {true, true};
        io->send_bool(cont, 2);
    }

    io->flush();

    int len = additive_share.length();

    for (int i = 0; i < 64 - len; i++) {
        additive_share = "0" + additive_share;
    }

    cout << party << ": " << additive_share << endl;

    string a = "000000000000000000000000000000000000000000000000000000000000000000";
    string b = "000000000000000000000000000000000000000000000000000000000000000000";

    string a_mask = "000000000000000000000000000000000000000000000000000000000000000000";
    string b_mask = "000000000000000000000000000000000000000000000000000000000000000000";

    string _p = "00FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF";

    if (party == ALICE) {
        a = additive_share;
        a = "00" + a;
        a = hex_string_reverse_bits(a);
        a_mask = hex_string_reverse_bits(generate_random_hex_string(64));
        a_mask = a_mask + "00";
    } else {
        b = additive_share;
        b = "00" + b;
        b = hex_string_reverse_bits(b);
        b_mask = hex_string_reverse_bits(generate_random_hex_string(64));
        b_mask = b_mask + "00";
    }

    _p = hex_string_reverse_bits(_p);

    string res = add_2_xor_circuit->online_computation(
        b + b_mask + _p + a + a_mask + _p
    );

    cout << party << " gets 0x" << res << endl;

    string out = (party == ALICE) ? a_mask : xorHexStrings(res, b_mask);

    out = hex_string_reverse_bits(out);

    cout << out << endl;

    delete io;
    return out;
}

EmpTlsPrf384::EmpTlsPrf384(int _party, const char *IP, int port, bool _debug) {
    party = _party;
    hmac1 = new EmpAg2pcGarbledCircuit(hmac1_cfn, _party, IP, port, _debug);
    hmac2 = new EmpAg2pcGarbledCircuit(hmac2_cfn, _party, IP, port, _debug);
    hmac3 = new EmpAg2pcGarbledCircuit(hmac3_cfn, _party, IP, port, _debug);
    hmac4 = new EmpAg2pcGarbledCircuit(hmac4_cfn, _party, IP, port, _debug);
    hmac5 = new EmpAg2pcGarbledCircuit(hmac5_cfn, _party, IP, port, _debug);
    DEBUG = _debug;
}

void EmpTlsPrf384::offline_computation() {
    hmac1->offline_computation();
    hmac2->offline_computation();
    hmac3->offline_computation();
    hmac4->offline_computation();
    hmac5->offline_computation();
}

string EmpTlsPrf384::online_computation(string rnd_s, string rnd_c, string share, string check_output) {
    string alice_mask = "0000000000000000000000000000000000000000000000000000000000000000";
    string bob_mask = "0000000000000000000000000000000000000000000000000000000000000000";

    if (party == ALICE) {
        alice_mask = generate_random_hex_string(64);
    } else {
        bob_mask = generate_random_hex_string(64);
    }

    string msg = "master secret";
    msg = utf8_to_hex(msg);
    string r_s = rnd_c;
    string r_c = rnd_s;

    string share_1 = "0000000000000000000000000000000000000000000000000000000000000000";
    string share_2 = "0000000000000000000000000000000000000000000000000000000000000000";

    if (party == ALICE) {
        share_1 = share;
    } else {
        share_2 = share;
    }

    string V = msg + r_s + r_c;
    string V_zeros = "";

    for (int i = 0; i < V.length(); i++) {
        V_zeros += "0";
    }

    int len_share_1 = share_1.length();
    for (int i = 0; i < 128 - len_share_1; i++) {
        share_1 += "0";
        share_2 += "0";
    }

    string ipad = "";
    string opad = "";
    for (int i = 0; i < 64; i++) {
        ipad += IPAD;
        opad += OPAD;
    }

    string share_1_ipad = xorHexStrings(share_1, ipad);
    string share_1_opad = xorHexStrings(share_1, opad);

    string share_2_ipad = share_2;
    string share_2_opad = share_2;

    V = sha256_padding(share_1_ipad + V).substr(share_1_ipad.length());
    
    if (DEBUG) cout << "cal f_H(IV_0, k xor opad)" << endl;
    string f_H_opad = hmac1->online_computation(
        bob_mask + share_2_opad + iv_0 + alice_mask + share_1_opad
    ).substr(64, 64);

    string f_H_opad_alice = xorHexStrings(f_H_opad, alice_mask);
    string f_H_opad_bob = bob_mask;

    if (DEBUG) cout << "cal f_H(IV_0, k xor ipad)" << endl;
	string f_H_ipad = hmac2->online_computation(
        share_2_ipad + iv_0 + share_1_ipad
    ).substr(64, 64);

    if (DEBUG) cout << "cal rest of f_H(f_H(f_H(IV_0, k xor ipad), m_1), m_2)" << endl;
	string f_H_ipad_V = plaintext_sha256(
		V,
		f_H_ipad
	);

    if (DEBUG) cout << "cal f_H(f_H_opad, f_H_ipad_V)" << endl;
    f_H_ipad_V = sha256_padding(share_1_opad + f_H_ipad_V).substr(share_1_opad.length());
	string M_1 = hmac3->online_computation(
        f_H_opad_bob + f_H_opad_alice + f_H_ipad_V
    ).substr(0, 64);

    if (DEBUG) cout << "cal f_H_ipad_M reuse the component" << endl;
    string M_1_padded = sha256_padding(share_1_ipad + M_1).substr(share_1_ipad.length());
    string f_H_ipad_M = plaintext_sha256(
        M_1_padded,
        f_H_ipad
    );

    if (DEBUG) cout << "cal f_H(f_H_opad, f_H_ipad_M)" << endl;
    f_H_ipad_M = sha256_padding(share_1_opad + f_H_ipad_M).substr(share_1_opad.length());
    if (DEBUG) {
        cout << "length of f_H_opad_alice: " << f_H_opad_alice.length() * 4 << endl;
        cout << "length of f_H_opad_bob: " << f_H_opad_bob.length() * 4 << endl;
        cout << "length of f_H_ipad_M: " << f_H_ipad_M.length() * 4 << endl;
    }

    string M_2 = hmac4->online_computation(
        f_H_opad_bob + f_H_opad_alice + f_H_ipad_M
    ).substr(0, 64);

    if (DEBUG) cout << "cal f_H_ipad_M_1_V reuse the component" << endl;
    string M_1_V = sha256_padding(share_1_ipad + M_1 + msg + r_s + r_c).substr(share_1_ipad.length());
    string f_H_ipad_M_1_V = plaintext_sha256(
        M_1_V,
        f_H_ipad
    );

    if (DEBUG) cout << "cal f_H_ipad_M_2_V reuse the component" << endl;
    string M_2_V = sha256_padding(share_1_ipad + M_2 + msg + r_s + r_c).substr(share_1_ipad.length());
    string f_H_ipad_M_2_V = plaintext_sha256(
        M_2_V,
        f_H_ipad
    );

    if (DEBUG) cout << "cal ms & h(server key)" << endl;
    alice_mask = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    bob_mask = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    if (party == ALICE) {
        alice_mask = generate_random_hex_string(96);
    } else {
        bob_mask = generate_random_hex_string(96);
    }
    
    f_H_ipad_M_1_V = sha256_padding(share_1_opad + f_H_ipad_M_1_V).substr(share_1_opad.length());
    f_H_ipad_M_2_V = sha256_padding(share_1_opad + f_H_ipad_M_2_V).substr(share_1_opad.length());

    if (DEBUG) {
        cout << "length of f_H_opad_alice: " << f_H_opad_alice.length() * 4 << endl;
        cout << "length of f_H_ipad_M_1_V: " << f_H_ipad_M_1_V.length() * 4 << endl;
        cout << "length of alice_mask: " << alice_mask.length() * 4 << endl;
        cout << "length of f_H_opad_bob: " << f_H_opad_bob.length() * 4 << endl;
        cout << "length of f_H_ipad_M_2_V: " << f_H_ipad_M_2_V.length() * 4 << endl;
        cout << "length of bob_mask: " << bob_mask.length() * 4 << endl;
    }

    string ms = hmac5->online_computation(
        f_H_opad_bob + f_H_ipad_M_1_V + bob_mask + f_H_opad_alice + f_H_ipad_M_2_V + alice_mask
    );

    string ms_share = (party == ALICE) ? xorHexStrings(ms, alice_mask) : bob_mask;

    return ms_share;
}

EmpTlsPrf320::EmpTlsPrf320(int _party, const char *IP, int port, bool _debug) {
    party = _party;
    hmac1 = new EmpAg2pcGarbledCircuit(hmac1_cfn, _party, IP, port, _debug);
    hmac2 = new EmpAg2pcGarbledCircuit(hmac2_cfn, _party, IP, port, _debug);
    hmac3 = new EmpAg2pcGarbledCircuit(hmac3_cfn, _party, IP, port, _debug);
    hmac4 = new EmpAg2pcGarbledCircuit(hmac4_cfn, _party, IP, port, _debug);
    hmac5 = new EmpAg2pcGarbledCircuit(hmac5_cfn, _party, IP, port, _debug);
    DEBUG = _debug;
}

void EmpTlsPrf320::offline_computation() {
    hmac1->offline_computation();
    hmac2->offline_computation();
    hmac3->offline_computation();
    hmac4->offline_computation();
    hmac5->offline_computation();
}

string EmpTlsPrf320::online_computation(string rnd_s, string rnd_c, string share, string check_output) {
    string alice_mask = "0000000000000000000000000000000000000000000000000000000000000000";
    string bob_mask = "0000000000000000000000000000000000000000000000000000000000000000";

    if (party == ALICE) {
        alice_mask = generate_random_hex_string(64);
    } else {
        bob_mask = generate_random_hex_string(64);
    }

	string msg = "key expansion";
	msg = utf8_to_hex(msg);
    string r_s = rnd_s;
	string r_c = rnd_c;

    string share_1 = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    string share_2 = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    if (party == ALICE) {
        share_1 = share;
    } else {
        share_2 = share; 
    }

    string V = msg + r_s + r_c;
    string V_zeros = "";

    for (int i = 0; i < V.length(); i++) {
        V_zeros += "0";
    }

    int len_share_1 = share_1.length();
    for (int i = 0; i < 128 - len_share_1; i++) {
        share_1 += "0";
        share_2 += "0";
    }

    string ipad = "";
    string opad = "";
    for (int i = 0; i < 64; i++) {
        ipad += IPAD;
        opad += OPAD;
    }

    string share_1_ipad = xorHexStrings(share_1, ipad);
    string share_1_opad = xorHexStrings(share_1, opad);

    string share_2_ipad = share_2;
    string share_2_opad = share_2;

    V = sha256_padding(share_1_ipad + V).substr(share_1_ipad.length());

    if (DEBUG) cout << "cal f_H(IV_0, k xor opad)" << endl;
    string f_H_opad = hmac1->online_computation(
        bob_mask + share_2_opad + iv_0 + alice_mask + share_1_opad
    ).substr(64, 64);

    string f_H_opad_alice = xorHexStrings(f_H_opad, alice_mask);
    string f_H_opad_bob = bob_mask;

    if (DEBUG) cout << "cal f_H(IV_0, k xor ipad)" << endl;
    string f_H_ipad = hmac2->online_computation(
		share_2_ipad + iv_0 + share_1_ipad
	).substr(64, 64);

    if (DEBUG) cout << "cal rest of f_H(f_H(f_H(IV_0, k xor ipad), m_1), m_2)" << endl;
	string f_H_ipad_V = plaintext_sha256(
		V,
		f_H_ipad
	);

    if (DEBUG) cout << "cal f_H(f_H_opad, f_H_ipad_V)" << endl;
    f_H_ipad_V = sha256_padding(share_1_opad + f_H_ipad_V).substr(share_1_opad.length());
    string M_1 = hmac3->online_computation(
        f_H_opad_bob + f_H_opad_alice + f_H_ipad_V
    ).substr(0, 64);

    if (DEBUG) cout << "cal f_H_ipad_M reuse the component" << endl;
    string M_1_padded = sha256_padding(share_1_ipad + M_1).substr(share_1_ipad.length());
    string f_H_ipad_M = plaintext_sha256(
        M_1_padded,
        f_H_ipad
    );

    if (DEBUG) cout << "cal f_H(f_H_opad, f_H_ipad_M)" << endl;
    f_H_ipad_M = sha256_padding(share_1_opad + f_H_ipad_M).substr(share_1_opad.length());
    if (DEBUG) {
        cout << "length of f_H_opad_alice: " << f_H_opad_alice.length() * 4 << endl;
        cout << "length of f_H_opad_bob: " << f_H_opad_bob.length() * 4 << endl;
        cout << "length of f_H_ipad_M: " << f_H_ipad_M.length() * 4 << endl;
    } 
    string M_2 = hmac4->online_computation(
        f_H_opad_bob + f_H_opad_alice + f_H_ipad_M
    ).substr(0, 64);

    if (DEBUG) cout << "cal f_H_ipad_M_1_V reuse the component" << endl;
    string M_1_V = sha256_padding(share_1_ipad + M_1 + msg + r_s + r_c).substr(share_1_ipad.length());
    string f_H_ipad_M_1_V = plaintext_sha256(
        M_1_V,
        f_H_ipad
    );

    if (DEBUG) cout << "cal f_H_ipad_M_2_V reuse the component" << endl;
    string M_2_V = sha256_padding(share_1_ipad + M_2 + msg + r_s + r_c).substr(share_1_ipad.length());
    string f_H_ipad_M_2_V = plaintext_sha256(
        M_2_V,
        f_H_ipad
    );

    if (DEBUG) cout << "cal ms & h(server key)" << endl;
    alice_mask = "00000000000000000000000000000000000000000000000000000000000000000000000000000000";
    bob_mask = "00000000000000000000000000000000000000000000000000000000000000000000000000000000";

    if (party == ALICE) {
        alice_mask = generate_random_hex_string(64) + "0000000000000000";
    } else {
        bob_mask = generate_random_hex_string(80);
    }
    
    f_H_ipad_M_1_V = sha256_padding(share_1_opad + f_H_ipad_M_1_V).substr(share_1_opad.length());
    f_H_ipad_M_2_V = sha256_padding(share_1_opad + f_H_ipad_M_2_V).substr(share_1_opad.length());

    if (DEBUG) {
        cout << "length of f_H_opad_alice: " << f_H_opad_alice.length() * 4 << endl;
        cout << "length of f_H_ipad_M_1_V: " << f_H_ipad_M_1_V.length() * 4 << endl;
        cout << "length of alice_mask: " << alice_mask.length() * 4 << endl;
        cout << "length of f_H_opad_bob: " << f_H_opad_bob.length() * 4 << endl;
        cout << "length of f_H_ipad_M_2_V: " << f_H_ipad_M_2_V.length() * 4 << endl;
        cout << "length of bob_mask: " << bob_mask.length() * 4 << endl;
    }
    string ms_str = hmac5->online_computation(
        f_H_opad_bob + f_H_ipad_M_1_V + bob_mask + f_H_opad_alice + f_H_ipad_M_2_V + alice_mask
    );

    string ms = ms_str.substr(0, 80);
    string hash_server_key = ms_str.substr(80, 64);
    string ms_share = (party == ALICE) ? alice_mask : xorHexStrings(ms, bob_mask);

    if (party == ALICE) {
        cout << ms_share << endl;
        cout << hash_server_key << endl;
    } else {
        cout << ms_share << endl;
        cout << hash_server_key << endl;
    }

	return ms_share + hash_server_key;
}

EmpTlsPrfCFSF::EmpTlsPrfCFSF(int _party, const char *IP, int port, string _msg, bool _debug) {
    party = _party;
    hmac1 = new EmpAg2pcGarbledCircuit(hmac1_cfn, _party, IP, port, _debug);
    hmac2 = new EmpAg2pcGarbledCircuit(hmac2_cfn, _party, IP, port, _debug);
    hmac3 = new EmpAg2pcGarbledCircuit(hmac3_cfn, _party, IP, port, _debug);
    hmac4 = new EmpAg2pcGarbledCircuit(hmac4_cfn, _party, IP, port, _debug);
    hmac5 = new EmpAg2pcGarbledCircuit(hmac5_cfn, _party, IP, port, _debug);
    DEBUG = _debug;
    assert(_msg == "client finished" || _msg == "server finished");
    msg = _msg;
}

void EmpTlsPrfCFSF::offline_computation() {
    hmac1->offline_computation();
    hmac2->offline_computation();
    hmac3->offline_computation();
    hmac4->offline_computation();
    hmac5->offline_computation();
}

string EmpTlsPrfCFSF::online_computation(string seed, string share, string check_output) {
    string alice_mask = "0000000000000000000000000000000000000000000000000000000000000000";
    string bob_mask = "0000000000000000000000000000000000000000000000000000000000000000";

    if (party == ALICE) {
        alice_mask = generate_random_hex_string(64);
    } else {
        bob_mask = generate_random_hex_string(64);
    }

	msg = utf8_to_hex(msg);

    string share_1 = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    string share_2 = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    if (party == ALICE) {
        share_1 = share;
    } else {
        share_2 = share; 
    }

    string V = msg + seed;
    string V_zeros = "";

    for (int i = 0; i < V.length(); i++) {
        V_zeros += "0";
    }

    int len_share_1 = share_1.length();
    for (int i = 0; i < 128 - len_share_1; i++) {
        share_1 += "0";
        share_2 += "0";
    }

    string ipad = "";
    string opad = "";
    for (int i = 0; i < 64; i++) {
        ipad += IPAD;
        opad += OPAD;
    }

    string share_1_ipad = xorHexStrings(share_1, ipad);
    string share_1_opad = xorHexStrings(share_1, opad);

    string share_2_ipad = share_2;
    string share_2_opad = share_2;

    V = sha256_padding(share_1_ipad + V).substr(share_1_ipad.length());

    if (DEBUG) cout << "cal f_H(IV_0, k xor opad)" << endl;
    string f_H_opad = hmac1->online_computation(
        bob_mask + share_2_opad + iv_0 + alice_mask + share_1_opad
    ).substr(64, 64);

    string f_H_opad_alice = xorHexStrings(f_H_opad, alice_mask);
    string f_H_opad_bob = bob_mask;

    if (DEBUG) cout << "cal f_H(IV_0, k xor ipad)" << endl;
    string f_H_ipad = hmac2->online_computation(
		share_2_ipad + iv_0 + share_1_ipad
	).substr(64, 64);

    if (DEBUG) cout << "cal rest of f_H(f_H(f_H(IV_0, k xor ipad), m_1), m_2)" << endl;
	string f_H_ipad_V = plaintext_sha256(
		V,
		f_H_ipad
	);

    if (DEBUG) cout << "cal f_H(f_H_opad, f_H_ipad_V)" << endl;
    f_H_ipad_V = sha256_padding(share_1_opad + f_H_ipad_V).substr(share_1_opad.length());
    string M_1 = hmac3->online_computation(
        f_H_opad_bob + f_H_opad_alice + f_H_ipad_V
    ).substr(0, 64);

    if (DEBUG) cout << "cal f_H_ipad_M reuse the component" << endl;
    string M_1_padded = sha256_padding(share_1_ipad + M_1).substr(share_1_ipad.length());
    string f_H_ipad_M = plaintext_sha256(
        M_1_padded,
        f_H_ipad
    );

    if (DEBUG) cout << "cal f_H(f_H_opad, f_H_ipad_M)" << endl;
    f_H_ipad_M = sha256_padding(share_1_opad + f_H_ipad_M).substr(share_1_opad.length());
    if (DEBUG) {
        cout << "length of f_H_opad_alice: " << f_H_opad_alice.length() * 4 << endl;
        cout << "length of f_H_opad_bob: " << f_H_opad_bob.length() * 4 << endl;
        cout << "length of f_H_ipad_M: " << f_H_ipad_M.length() * 4 << endl;
    } 

    string M_2 = hmac4->online_computation(
        f_H_opad_bob + f_H_opad_alice + f_H_ipad_M
    ).substr(0, 64);

    if (DEBUG) cout << "cal f_H_ipad_M_1_V reuse the component" << endl;
    string M_1_V = sha256_padding(share_1_ipad + M_1 + msg + seed).substr(share_1_ipad.length());
    string f_H_ipad_M_1_V = plaintext_sha256(
        M_1_V,
        f_H_ipad
    );

    if (DEBUG) cout << "cal f_H_ipad_M_2_V reuse the component" << endl;
    string M_2_V = sha256_padding(share_1_ipad + M_2 + msg + seed).substr(share_1_ipad.length());
    string f_H_ipad_M_2_V = plaintext_sha256(
        M_2_V,
        f_H_ipad
    );

    if (DEBUG) cout << "cal ms & h(server key)" << endl;
    alice_mask = "000000000000000000000000";
    bob_mask = "000000000000000000000000";

    if (party != ALICE) {
        bob_mask = generate_random_hex_string(24);
    } 
    
    f_H_ipad_M_1_V = sha256_padding(share_1_opad + f_H_ipad_M_1_V).substr(share_1_opad.length());
    f_H_ipad_M_2_V = sha256_padding(share_1_opad + f_H_ipad_M_2_V).substr(share_1_opad.length());

    if (DEBUG) {
        cout << "length of f_H_opad_alice: " << f_H_opad_alice.length() * 4 << endl;
        cout << "length of f_H_ipad_M_1_V: " << f_H_ipad_M_1_V.length() * 4 << endl;
        cout << "length of alice_mask: " << alice_mask.length() * 4 << endl;
        cout << "length of f_H_opad_bob: " << f_H_opad_bob.length() * 4 << endl;
        cout << "length of f_H_ipad_M_2_V: " << f_H_ipad_M_2_V.length() * 4 << endl;
        cout << "length of bob_mask: " << bob_mask.length() * 4 << endl;
    } 

    string ms_str = hmac5->online_computation(
        f_H_opad_bob + f_H_ipad_M_1_V + bob_mask + f_H_opad_alice + f_H_ipad_M_2_V + alice_mask
    );

    string ms_share = (party == ALICE) ? alice_mask : xorHexStrings(ms_str, bob_mask);

    cout << ms_share << endl;

	return ms_share;
}

EmpNaiveAesGcmEnc::EmpNaiveAesGcmEnc(int _party, const char *IP, int port, int _len_c, int _len_a, bool _debug) {
    string cfn = "AES/aes-gcm-" + to_string((int) _len_c / 128) + ".txt";
    aesgcm_circuit = new EmpAg2pcGarbledCircuit(cfn, _party, IP, port, _debug);
    party = _party;
    len_a_i = _len_a;
    len_c_i = _len_c;
    DEBUG = _debug;
}

void EmpNaiveAesGcmEnc::offline_computation() {
    aesgcm_circuit->offline_computation();
}

string EmpNaiveAesGcmEnc::online_computation(string m, string ad, string key_share, string iv_share) {
    int plain_block = (int) len_c_i / 128;
    int ad_block    = (int) len_a_i / 128;
    plain_block += (len_c_i % 128 == 0) ? 0 : 1;
    ad_block    += (len_a_i % 128 == 0) ? 0 : 1;

    string len_c = int_to_hex_16(m.length() * 4);
    string len_a = int_to_hex_16(ad.length() * 4);

    string io_bob_plaintext         = (party == ALICE) ? string(plain_block * 32, '0') : pad_hex_string(m);
    string io_bob_len_c             = "0000000000000000" + len_c;
    string io_bob_key_share         = (party == ALICE) ? string(32, '0') : reverse_hex_binary(key_share);
    string io_bob_counter_0_share   = (party == ALICE) ? string(32, '0') : reverse_hex_binary(iv_share + "00000001");
    string io_bob_padding_mask      = (party == ALICE) ? string(32, '0') : padding_mask(len_c_i);

    string io_alice_ad              = (party == ALICE) ? pad_hex_string(ad) : string(ad_block * 32, '0');
    string io_alice_len_a           = len_a + "0000000000000000";
    string io_alice_key_share       = (party == ALICE) ? reverse_hex_binary(key_share) : string(32, '0');
    string io_alice_counter_0_share = (party == ALICE) ? reverse_hex_binary(iv_share + "00000000") : string(32, '0');
    string io_alice_dummy           = string((plain_block - ad_block + 1) * 32, '0');

    string in = io_bob_plaintext + io_bob_len_c + io_bob_key_share + io_bob_counter_0_share + io_bob_padding_mask 
                    + io_alice_ad + io_alice_len_a + io_alice_key_share + io_alice_counter_0_share + io_alice_dummy;

    if (DEBUG) cout << in << endl;
    if (DEBUG) cout << in.length() * 4 << endl;

    string c = aesgcm_circuit->online_computation(in);

    cout << c.substr(0, plain_block * 32) << endl;
    cout << c.substr(plain_block * 32, 32) << endl;

    return c;
}

EmpNaiveAesGcmDec::EmpNaiveAesGcmDec(int _party, const char *IP, int port, int _len_c, int _len_a, bool _debug) {
    string cfn = "AES/aes-gcm-dec-" + to_string((int) _len_c / 128) + ".txt";
    aesgcm_circuit = new EmpAg2pcGarbledCircuit(cfn, _party, IP, port, _debug);
    party = _party;
    len_a_i = _len_a;
    len_c_i = _len_c;
    DEBUG = _debug;
}

void EmpNaiveAesGcmDec::offline_computation() {
    aesgcm_circuit->offline_computation();
}

string EmpNaiveAesGcmDec::online_computation(string c, string ad, string key_share, string iv_share, string tag) {
    int cipher_block = (int) len_c_i / 128;
    int ad_block    = (int) len_a_i / 128;
    cipher_block += (len_c_i % 128 == 0) ? 0 : 1;
    ad_block    += (len_a_i % 128 == 0) ? 0 : 1;

    string len_c = int_to_hex_16(c.length() * 4);
    string len_a = int_to_hex_16(ad.length() * 4);

    string io_bob_ciphertext        = (party == ALICE) ? string(cipher_block * 32, '0') : pad_hex_string(c);
    string io_bob_tag               = (party == ALICE) ? string(32, '0') : tag;
    string io_bob_len_c             = "0000000000000000" + len_c;
    string io_bob_key_share         = (party == ALICE) ? string(32, '0') : reverse_hex_binary(key_share);
    string io_bob_counter_0_share   = (party == ALICE) ? string(32, '0') : reverse_hex_binary(iv_share + "00000001");
    string io_bob_padding_mask      = (party == ALICE) ? string(32, '0') : padding_mask(len_c_i);

    string io_alice_auth_data       = (party == ALICE) ? pad_hex_string(ad) : string(ad_block * 32, '0');
    string io_alice_len_a           = len_a + "0000000000000000";
    string io_alice_key_share       = (party == ALICE) ? reverse_hex_binary(key_share) : string(32, '0');
    string io_alice_counter_0_share = (party == ALICE) ? reverse_hex_binary(iv_share + "00000000") : string(32, '0');
    string io_alice_dummy           = string((cipher_block - ad_block + 2) * 32, '0');

    string in = io_bob_ciphertext + io_bob_tag + io_bob_len_c + io_bob_key_share + io_bob_counter_0_share + io_bob_padding_mask 
                    + io_alice_auth_data + io_alice_len_a + io_alice_key_share + io_alice_counter_0_share + io_alice_dummy;
    if (DEBUG) cout << in << endl;
    if (DEBUG) cout << in.length() * 4 << endl;

    string m = aesgcm_circuit->online_computation(in);
    cout << m.substr(0, 1) << endl;
    cout << m.substr(1, (int) (len_c_i / 4)) << endl;

    return m.substr(0, (int) (len_c_i / 4 + 1));
}

EmpNaiveAesGcmPredicateEnc::EmpNaiveAesGcmPredicateEnc(int _party, const char *IP, int port, int _len_c, int _len_a, bool _debug) {
    string cfn = "AES/predicate-standard-aes-gcm-" + to_string((int) _len_c / 128) + ".txt";
    pre_aesgcm_circuit = new EmpAg2pcGarbledCircuit(cfn, _party, IP, port, _debug);
    party = _party;
    len_a_i = _len_a;
    len_c_i = _len_c;
    DEBUG = _debug;
}

void EmpNaiveAesGcmPredicateEnc::offline_computation() {
    pre_aesgcm_circuit->offline_computation();
}

string EmpNaiveAesGcmPredicateEnc::online_computation(string m, string ad, string key_share, string iv_share, string commitment, string r_com) {
    int plain_block = (int) len_c_i / 128;
    int ad_block    = (int) len_a_i / 128;
    plain_block += (len_c_i % 128 == 0) ? 0 : 1;
    ad_block    += (len_a_i % 128 == 0) ? 0 : 1;

    string len_c = int_to_hex_16(m.length() * 4);
    string len_a = int_to_hex_16(ad.length() * 4);

    string io_bob_plaintext         = (party == ALICE) ? string(plain_block * 32, '0') : pad_hex_string(m);
    string io_bob_len_c             = (party == ALICE) ? string(32, '0') : "0000000000000000" + len_c;
    string io_bob_key_share         = (party == ALICE) ? string(32, '0') : reverse_hex_binary(key_share);
    string io_bob_counter_0_share   = (party == ALICE) ? string(32, '0') : reverse_hex_binary(iv_share + "00000001");
    string io_bob_padding_mask      = (party == ALICE) ? string(32, '0') : padding_mask(len_c_i);
    string io_bob_dummy             = string((ad_block + 2) * 32, '0');

    string io_alice_plaintext       = (party == ALICE) ? pad_hex_string(m): string(plain_block * 32, '0');
    string io_alice_auth_data       = (party == ALICE) ? pad_hex_string(ad) : string(ad_block * 32, '0');
    string io_alice_len_a           = (party == ALICE) ? len_a + "0000000000000000" : string(32, '0');
    string io_alice_key_share       = (party == ALICE) ? reverse_hex_binary(key_share) : string(32, '0');
    string io_alice_counter_0_share = (party == ALICE) ? reverse_hex_binary(iv_share + "00000000") : string(32, '0');
    string io_alice_commitment      = (party == ALICE) ? commitment : string(64, '0');
    string io_alice_r_com           = (party == ALICE) ? r_com : string(32, '0');

    string in = io_bob_plaintext + io_bob_len_c + io_bob_key_share + io_bob_counter_0_share + io_bob_padding_mask + io_bob_dummy 
                    + io_alice_plaintext + io_alice_auth_data + io_alice_len_a + io_alice_key_share + io_alice_counter_0_share + io_alice_commitment + io_alice_r_com;
    
    if (DEBUG) cout << in << endl;
    if (DEBUG) cout << in.length() * 4 << endl;

    string c = pre_aesgcm_circuit->online_computation(in);

    cout << c.substr(0, 1) << endl;
    cout << c.substr(1, (int) len_c_i / 4) << endl;
    cout << c.substr(1 + plain_block * 32, 32) << endl;

    return c;
}

#endif