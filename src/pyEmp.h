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

#define DEBUG false
#define LOG false

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
    void mta(BIGNUM **share, IKNP<NetIO> *ot, int party, NetIO *io, BIGNUM **data, const int len_data, BIGNUM *P, BN_CTX *ctx);

public:
    EmpECtF(int _party, const char *IP, int port, bool _debug = false);
    void offline_computation();
    string online_computation(string hin = "", string check_output = "");
};


class EmpGcm2pc {
private:

public:

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

EmpECtF::EmpECtF(int _party, const char *IP, int port, bool _debug) {
    // load the add to xor circuit
    string cfn = "ECtF/add_2_xor_p256.txt";
    add_2_xor_circuit = new EmpAg2pcGarbledCircuit(cfn, _party, IP, port, _debug);
    party = _party;
    io = add_2_xor_circuit->get_NetIO();
    ot = new IKNP<NetIO>(io, true);     // malicious ot
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
#endif