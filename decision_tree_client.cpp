//
// Created by Ruochen WANG on 1/4/2020.
//

#include <iostream>
#include <algorithm>
#include <vector>

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Common/BitVector.h>
#include <cryptoTools/Crypto/PRNG.h>
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtSender.h"
#include "libOTe/NChooseOne//Kkrt/KkrtNcoOtReceiver.h"
#include "libOTe/Base/SimplestOT.h"

#include "decision_tree.h"
#include "secret_sharing.h"
#include "utils.h"
#include "network.h"

using namespace osuCrypto;
extern gmp_randclass gmp_prn;

void ss_decrypt_client(int &plain, int share, NetAdapter *net) {
    // client send the int share first, then the server send back;
    net->send(reinterpret_cast<unsigned char *>(&share), sizeof(share));
    net->recv(reinterpret_cast<unsigned char *>(&plain), sizeof(share));
//    plain = mod_bit(share[0] + share[1]);
}

void secure_mul_client(int as, int bs, int &ab_s, const triplet_b &tri, NetAdapter *net) {
    int e, es, f, fs;
    es = mod_bit(as - tri.us[1]);
    fs = mod_bit(bs - tri.gs[1]);

    ss_decrypt_client(e, es, net);
    ss_decrypt_client(f, fs, net);

    ab_s = mod_bit(1 * e * f + e * tri.gs[1] + f * tri.us[1] + tri.zs[1]);
}

void ss_decrypt_client(mpz_class &plain, mpz_class share, NetAdapter *net) {
    // client send the int share first, then the server send back;
    send_mpz_net(share, net);
    get_mpz_net(plain, net);
//    net->send(reinterpret_cast<unsigned char *>(&share), sizeof(share));
//    net->recv(reinterpret_cast<unsigned char *>(&plain), sizeof(share));
//    plain = mod_bit(share[0] + share[1]);
}

void secure_mul_client(mpz_class as, mpz_class bs, mpz_class &ab_s, const triplet_z &tri, NetAdapter *net) {
    mpz_class e, es, f, fs;
    es = as - tri.us[1];
    mod_2exp(es, CONFIG_L);
    fs = bs - tri.gs[1];
    mod_2exp(fs, CONFIG_L);

    ss_decrypt_client(e, es, net);
    ss_decrypt_client(f, fs, net);

    ab_s = 1 * e * f + e * tri.gs[1] + f * tri.us[1] + tri.zs[1];
    mod_2exp(ab_s, CONFIG_L);
}

inline void secure_feature_index_sharing_client(uint64_t index, uint64_t s, std::vector<uint64_t> &feature_share, NetAdapter* net) {
    // 2)
    static uint64_t i_prime;
    get_u64_net(i_prime, net);
    // 3)
    static uint64_t i_origin_with_mask = i_prime + feature_share[index] + s;
    send_u64_net(i_origin_with_mask, net);

}
inline uint64_t secure_feature_index_sharing_server(uint64_t index,uint64_t feature_count, uint64_t random, std::vector<uint64_t> & feature_share, NetAdapter* net) {
    // 2)
    static uint64_t i_prime = feature_share[index] + random;
    send_u64_net(i_prime, net);
    // 3)
    static uint64_t i_origin_with_mask;
    get_u64_net(i_origin_with_mask, net);
    // 4)
    static uint64_t i_origin_prime = i_origin_with_mask - random;
    i_origin_prime %= feature_count;
    return i_origin_prime;
}
void secure_feature_selection_with_one_node_client(std::vector<uint64_t>& p, std::vector<uint64_t>& feature_share, uint64_t &selected_feature, int index, NetAdapter *net,KkrtNcoOtSender &sender, KkrtNcoOtReceiver & receiver,PRNG &prng, Channel &chl){

    int feature_count = p.size();
    int m = feature_share.size();
    std::vector<uint64_t> p_prime;
    uint64_t s, r;

    s = prng.get<uint64_t>();
    r = prng.get<uint64_t>();
    p_prime.reserve(feature_count);

    // 1)
    for (int j = 0; j < feature_count; j++) {
        static uint64_t j_star;
        j_star = j + s;
        j_star %= feature_count;
        p_prime[j] = p[j_star] + r;
    }

    // 2,3,4)
    for (int i = 0; i < m; i++)
        secure_feature_index_sharing_client(i, s, feature_share, net);


    // 5)
    // client C1 acts like a sender
    Matrix<block> otMat(m, feature_count);
    for (int j = 0; j < m; j++)
    for (int i= 0; i < feature_count; i++) {
        otMat[j][i] = toBlock(p_prime[i]);
    }
    sender.sendChosen(otMat, prng, chl);

    // 6)
    uint64_t random;
    std::vector<uint64_t> i_origin_primes(m);
    for (int i = 0; i < m; i++) {
        random = prng.get<uint64_t>();
        i_origin_primes[i] = secure_feature_index_sharing_server(i, feature_count, random, feature_share, net);
    }
    std::vector<block> recvMsgs(m);
    receiver.receiveChosen(feature_count, recvMsgs, i_origin_primes, prng, chl);

    std::vector<uint64_t> p_prime_0(m);
    for (int i = 0; i < m; i++) {
        p_prime_0[i] = block_to_u64(recvMsgs[i]);
    }

    // 7)
    uint64_t random_prime ;
    std::vector<uint64_t> p_stars(m);
    for(int i = 0; i < m; i++) {
        random_prime = prng.get<uint64_t>();

        p_stars[i] = p_prime_0[i] - r - random_prime;
        send_u64_net(p_stars[i], net);
    }

    for (int i = 0; i < m; i++) {
        get_u64_net(p_stars[i], net);
        p_stars[i] += p_prime_0[i] - r;
    }

//    std::cout << "done 1 round\n";
}

inline void
carry_calculation(int G_star[2], int P_star[2], int G1[2], int P1[2], int G2[2], int P2[2], const triplet_b &tri_b) {
    int gp[2], pp[2];
    secure_mul(G2, P1, gp, tri_b);
    secure_mul(P1, P2, pp, tri_b);
    SS_DO(G_star[i] = G1[i] + gp[i];
                  P_star[i] = pp[i];)
}

inline void
carry_calculation_client(int &G_star, int &P_star, int G1, int P1, int G2, int P2, const triplet_b &tri_b,
                         NetAdapter *net) {
    int gp, pp;
    secure_mul_client(G2, P1, gp, tri_b, net);
    secure_mul_client(P1, P2, pp, tri_b, net);
    G_star = G1 + gp;
    P_star = pp;
}


void secure_node_eval_with_look_ahead_carry_adder_client(const mpz_class x, const mpz_class y, const triplet_z &tri_z,
                                                         const triplet_b &tri_b, NetAdapter *net) {

    mpz_class delta;

    // 1) compute delta over secrete shares
    delta = y - x;
    mod_2exp(delta, CONFIG_L);

    // 3, 4) setup round for secure carry computation
//    int (*G)[2] = new int[CONFIG_L][2];
//    int (*P)[2] = new int[CONFIG_L][2];
    int G[CONFIG_L], P[CONFIG_L];
    int a_q, b_q;
    a_q = 0;
//    b_q[0] = 0;

    for (int i = 0; i < CONFIG_L; i++) {
//        a_q[0] = bit(delta, i);
        b_q = bit(delta, i);
        secure_mul_client(a_q, b_q, G[i], tri_b, net);
//        P[i][0] = a_q;
        P[i] = b_q;
    }

    // 5)
    int G1[CONFIG_L / 2], P1[CONFIG_L / 2];
    G1[0] = G[0];
    P1[0] = P[0];

    // 6) 32 round
    for (int i = 1; i < CONFIG_L / 2; i++) {
        carry_calculation_client(G1[i], P1[i], G[2 * i], P[2 * i], G[2 * i - 1], P[2 * i - 1], tri_b, net);
    }

    // 7) 16 round
    int G2[CONFIG_L / 4], P2[CONFIG_L / 4];
    for (int i = 0; i < CONFIG_L / 4; i++) {
        carry_calculation_client(G2[i], P2[i], G1[2 * i + 1], P1[2 * i + 1], G1[2 * i], P1[2 * i], tri_b, net);
    }

    // 8) 8 round
    int G3[CONFIG_L / 8], P3[CONFIG_L / 8];
    for (int i = 0; i < CONFIG_L / 8; i++) {
        carry_calculation_client(G3[i], P3[i], G2[2 * i + 1], P2[2 * i + 1], G2[2 * i], P2[2 * i], tri_b, net);
    }

    // 9) 4 round
    int G4[CONFIG_L / 16], P4[CONFIG_L / 16];
    for (int i = 0; i < CONFIG_L / 16; i++) {
        carry_calculation_client(G4[i], P4[i], G3[2 * i + 1], P3[2 * i + 1], G3[2 * i], P3[2 * i], tri_b, net);
    }

    // 10) 2 round
    int G5[CONFIG_L / 32], P5[CONFIG_L / 32];
    for (int i = 0; i < CONFIG_L / 32; i++) {
        carry_calculation_client(G5[i], P5[i], G4[2 * i + 1], P4[2 * i + 1], G4[2 * i], P4[2 * i], tri_b, net);
    }

    // 11)
    int G60;
    secure_mul_client(G5[0], P5[1], G60, tri_b, net);
    G60 += G5[1];

    // 12)
    mpz_class v;
    v = G60 + bit(delta, CONFIG_L - 1);

//    std::cout << "phase 2\n";
}

void secure_inference_generation_client(int decision[], mpz_class value[], int depth, mpz_class result,
                                        const triplet_b &tri_b, const triplet_z &tri_z, NetAdapter *net) {
    unsigned long long num_of_node = (1 << depth) - 1;
    unsigned long long num_of_value = num_of_node + 1;

    // 1)
    auto E_L = new int[num_of_node];
    auto E_R = new int[num_of_node];

    for (int j = 0; j < num_of_node; j++) {
        E_L[j] = decision[j];
        E_R[j] = decision[j];
    }

    // 2)

    auto G_2 = new int[2];
    G_2[0] = E_L[0];
    G_2[1] = E_R[0];
//    int cur_node = 0;
    for (int d = 1; d < depth; d++) {
//        int num_layer_node = (1 << d) - 1;
        int layer_node_count = 1 << d;
        auto cur_layer = new int[layer_node_count * 2];
        for (int node = 0; node < layer_node_count; node++) {
            int multiple = 0;
            secure_mul_client(G_2[node], E_R[layer_node_count + node - 1], multiple, tri_b, net);
            cur_layer[node * 2 + 1] = multiple;
            secure_mul_client(G_2[node], E_L[layer_node_count + node - 1], multiple, tri_b, net);
            cur_layer[node * 2] = multiple;
        }
        delete[] G_2;
        G_2 = cur_layer;
    }

    // 3)
    auto H1 = new mpz_class[num_of_value];
    auto H2 = new mpz_class[num_of_value];
    auto G = new mpz_class[num_of_value];
    mpz_class tmp;
    for (int z = 0; z < num_of_value; z++) {
        // a)
//        H1[z] = G_2[z];
        H1[z] = 0;
//        H2[z] = 0;
        H2[z] = G_2[z];
        secure_mul_client(H1[z], H2[z], tmp, tri_z, net);

        // b)
        G[z] = H1[z] + H2[z] - 2 * tmp;
    }


    // 4)
    auto u_stars = new mpz_class[num_of_value];
    result = 0;
    for (int z = 0; z < num_of_value; z++) {
        secure_mul_client(G[z], value[z], u_stars[z], tri_z, net);
        result += u_stars[z];
    }

    delete[] E_L;
    delete[] E_R;
    delete[] G_2;
    delete[] H1;
    delete[] H2;
    delete[] G;
    delete[] u_stars;
//    std::cout << "phase 3\n";
}