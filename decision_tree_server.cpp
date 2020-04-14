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

void ss_decrypt_server(int &plain, int share, NetAdapter *net) {

    // client send the int share first, then the server send back;
    int recv_share;
    net->recv(reinterpret_cast<unsigned char *>(&recv_share), sizeof(recv_share));
    plain = mod_bit(share + recv_share);
    net->send(reinterpret_cast<unsigned char *>(&plain), sizeof(plain));
}

void ss_decrypt_server_batch(int plain[], int share[], int m, NetAdapter *net) {
    int *recv_share = new int[m];
    net->recv(reinterpret_cast<unsigned char *> (recv_share), sizeof(int) * m);
    for (int i = 0; i < m; i++)
        plain[i] = mod_bit(share[i] + recv_share[i]);
    net->send(reinterpret_cast<unsigned char *>(plain), sizeof(int) * m);
    delete[] recv_share;
}

void secure_mul_server(int as, int bs, int &ab_s, const triplet_b &tri, NetAdapter *net) {
    int e, es, f, fs;
    es = mod_bit(as - tri.us[0]);
    fs = mod_bit(bs - tri.gs[0]);

    ss_decrypt_server(e, es, net);
    ss_decrypt_server(f, fs, net);

    ab_s = mod_bit(0 * e * f + e * tri.gs[0] + f * tri.us[0] + tri.zs[0]);
}

void secure_mul_server_batch(int as[], int bs[], int ab_s[], int m, const triplet_b &tri, NetAdapter *net) {
    int *e = new int[m];
    int *es = new int[m];
    int *f = new int[m];
    int *fs = new int[m];

    for (int i = 0; i < m; i++) {
        es[i] = mod_bit(as[i] - tri.us[0]);
        fs[i] = mod_bit(bs[i] - tri.gs[0]);
    }
    ss_decrypt_server_batch(e, es, m, net);
    ss_decrypt_server_batch(f, fs, m, net);

    for (int i = 0; i < m; i++) {
        ab_s[i] = mod_bit(0 * e[i] * f[i] + e[i] * tri.gs[0] + f[i] * tri.us[0] + tri.zs[0]);
    }
    delete[] e;
    delete[] es;
    delete[] f;
    delete[] fs;
}

void secure_mul_server_batch(mpz_class as[], mpz_class bs[], mpz_class ab_s[], int m, const triplet_b &tri, NetAdapter *net) {
    int * as_int = new int[m];
    int * bs_int = new int[m];
    int *ab_s_int = new int[m];
    for (int i = 0; i < m; i++) {
        as_int[i] = mpz_to_u64(as[i]);
        bs_int[i] = mpz_to_u64(bs[i]);
    }
    secure_mul_server_batch(as_int, bs_int, ab_s_int, m, tri, net);
    for (int i = 0; i < m; i++) {
        ab_s[i] = ab_s_int[i];
    }

}
void ss_decrypt_server(mpz_class &plain, mpz_class share, NetAdapter *net) {

    // client send the int share first, then the server send back;
    mpz_class recv_share;
    get_mpz_net(recv_share, net);
    plain = share + recv_share;
    mod_2exp(plain, CONFIG_L);
    send_mpz_net(plain, net);
}

void secure_mul_server(mpz_class as, mpz_class bs, mpz_class &ab_s, const triplet_z &tri, NetAdapter *net) {
    mpz_class e, es, f, fs;
    es = as - tri.us[0];
    mod_2exp(es, CONFIG_L);
    fs = bs - tri.gs[0];
    mod_2exp(fs, CONFIG_L);

    ss_decrypt_server(e, es, net);
    ss_decrypt_server(f, fs, net);

    ab_s = 0 * e * f + e * tri.gs[0] + f * tri.us[0] + tri.zs[0];
    mod_2exp(ab_s, CONFIG_L);
}

inline uint64_t secure_feature_index_sharing_server(uint64_t index, uint64_t feature_count, uint64_t random,
                                                    std::vector<uint64_t> &feature_share, NetAdapter *net) {
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

inline void
secure_feature_index_sharing_client(uint64_t index, uint64_t s, std::vector<uint64_t> &feature_share, NetAdapter *net) {
    // 2)
    static uint64_t i_prime;
    get_u64_net(i_prime, net);
    // 3)
    static uint64_t i_origin_with_mask = i_prime + feature_share[index] + s;
    send_u64_net(i_origin_with_mask, net);

}

void secure_feature_selection_with_one_node_server(std::vector<uint64_t> &p, std::vector<uint64_t> &feature_share,
                                                   uint64_t &selected_feature, int index, NetAdapter *net,
                                                   osuCrypto::KkrtNcoOtSender &sender,
                                                   osuCrypto::KkrtNcoOtReceiver &receiver, osuCrypto::PRNG &prng,
                                                   osuCrypto::Channel &chl) {

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

    // 2, 3, 4)
    uint64_t random;

    std::vector<uint64_t> i_origin_primes(m);
    for (int i = 0; i < m; i++) {
        random = prng.get<uint64_t>();
        i_origin_primes[i] = secure_feature_index_sharing_server(i, feature_count, random, feature_share, net);
    }

    // 5)
//     1-n OT receive msg input recvMsgs vector
    std::vector<block> recvMsgs(m);
    receiver.receiveChosen(feature_count, recvMsgs, i_origin_primes, prng, chl);

    // 6)
    for (int i = 0; i < m; i++)
        secure_feature_index_sharing_client(i, s, feature_share, net);

    Matrix<block> otMat(m, feature_count);
    for (int j = 0; j < m; j++) {
        for (int i = 0; i < feature_count; i++) {
            otMat[j][i] = toBlock(p_prime[i]);
        }
    }
    sender.sendChosen(otMat, prng, chl);

    std::vector<uint64_t> p_prime_1(m);
    for (int i = 0; i < m; i++) {
        p_prime_1[i] = block_to_u64(recvMsgs[i]);
    }

    // 8)
    std::vector<uint64_t> p_stars(m);
    for (int i = 0; i < m; i++) {
        get_u64_net(p_stars[i], net);
        p_stars[i] += p_prime_1[i] - r;
    }

    uint64_t random_prime;
    for (int i = 0; i < m; i++) {
        random_prime = prng.get<uint64_t>();
        p_stars[i] = p_prime_1[i] - random_prime - r;
        send_u64_net(p_stars[i], net);
    }
//    std::cout << "phase 1\n";
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
carry_calculation_server(int &G_star, int &P_star, int G1, int P1, int G2, int P2, const triplet_b &tri_b,
                         NetAdapter *net) {
    int gp, pp;
    secure_mul_server(G2, P1, gp, tri_b, net);
    secure_mul_server(P1, P2, pp, tri_b, net);
    G_star = G1 + gp;
    P_star = pp;
}

void carry_calculation_server_batch(int G_star[], int P_star[], int G1[], int P1[], int G2[], int P2[], int m,
                                    const triplet_b &tri_b, NetAdapter *net) {
    int *gp = new int[m];
    int *pp = new int[m];
    secure_mul_server_batch(G2, P1, gp, m, tri_b, net);
    secure_mul_server_batch(P1, P2, pp, m, tri_b, net);
    for (int i = 0; i < m; i++) {
        G_star[i] = G1[i] + gp[i];
        P_star[i] = pp[i];
    }
    delete[] gp;
    delete[] pp;
}

void secure_node_eval_with_look_ahead_carry_adder_server(mpz_class x[], mpz_class y[], int m, const triplet_z &tri_z,
                                                         const triplet_b &tri_b, NetAdapter *net) {

//    mpz_class delta;
    std::vector<mpz_class> deltas(m);

    // 1) compute delta over secrete shares
//    delta = y - x;
//    mod_2exp(delta, CONFIG_L);

    for (int i = 0; i < m; i++) {
        deltas[i] = y - x;
        mod_2exp(deltas[i], CONFIG_L);
    }

    // 3, 4) setup round for secure carry computation
    int *G = new int[m * CONFIG_L];
    int *P = new int[m * CONFIG_L];

    int *a_q = new int[m * CONFIG_L];
    int *b_q = new int[m * CONFIG_L];
    memset(b_q, 0, sizeof(int) * m * CONFIG_L);
    for (int i = 0; i < m; i++) {
        for (int j = 0; j < CONFIG_L; j++)
            a_q[i * CONFIG_L + j] = bit(deltas[i], j);
    }
    secure_mul_server_batch(a_q, b_q, G, m * CONFIG_L, tri_b, net);
    memcpy(P, a_q, sizeof(int) * m * CONFIG_L);

    // 5)
    const int total_count = m * CONFIG_L;
    int *G1 = new int[total_count / 2];
    int *P1 = new int[total_count / 2];
    for (int i = 0; i < m; i++) {
        G1[i * CONFIG_L / 2] = G[i * CONFIG_L];
        P1[i * CONFIG_L / 2] = P[i * CONFIG_L];
    }
//    int G1[CONFIG_L / 2], P1[CONFIG_L / 2];
//    G1[0] = G[0];
//    P1[0] = P[0];

    // 6) 32 round

    int *tmp_g1 = new int[m * CONFIG_L / 2];
    int *tmp_g2 = new int[m * CONFIG_L / 2];
    int *tmp_p1 = new int[m * CONFIG_L / 2];
    int *tmp_p2 = new int[m * CONFIG_L / 2];
    for (int i = 0; i < m; i++) {
        for (int j = 1; j < CONFIG_L / 2; j++) {
            tmp_g1[i * CONFIG_L / 2 + j] = G[i * CONFIG_L / 2 + 2 * j];
            tmp_g2[i * CONFIG_L / 2 + j] = G[i * CONFIG_L / 2 + 2 * j - 1];
            tmp_p1[i * CONFIG_L / 2 + j] = P[i * CONFIG_L / 2 + 2 * j];
            tmp_p2[i * CONFIG_L / 2 + j] = P[i * CONFIG_L / 2 + 2 * j - 1];
        }
    }
    carry_calculation_server_batch(G1, P1, tmp_g1, tmp_p1, tmp_g2, tmp_p2, m * CONFIG_L / 2, tri_b, net);

    delete[] tmp_g1;
    delete[] tmp_g2;
    delete[] tmp_p1;
    delete[] tmp_p2;


    // 7) 16 round
    int *G2 = new int[m * CONFIG_L / 4];
    int *P2 = new int[m * CONFIG_L / 4];

    tmp_g1 = new int[m * CONFIG_L / 4];
    tmp_g2 = new int[m * CONFIG_L / 4];
    tmp_p1 = new int[m * CONFIG_L / 4];
    tmp_p2 = new int[m * CONFIG_L / 4];
    for (int i = 0; i < m; i++) {
        for (int j = 1; j < CONFIG_L / 4; j++) {
            tmp_g1[i * CONFIG_L / 4 + j] = G1[i * CONFIG_L / 4 + 2 * j];
            tmp_g2[i * CONFIG_L / 4 + j] = G1[i * CONFIG_L / 4 + 2 * j - 1];
            tmp_p1[i * CONFIG_L / 4 + j] = P1[i * CONFIG_L / 4 + 2 * j];
            tmp_p2[i * CONFIG_L / 4 + j] = P1[i * CONFIG_L / 4 + 2 * j - 1];
        }
    }
    carry_calculation_server_batch(G2, P2, tmp_g1, tmp_p1, tmp_g2, tmp_p2, m * CONFIG_L / 4, tri_b, net);

    delete[] tmp_g1;
    delete[] tmp_g2;
    delete[] tmp_p1;
    delete[] tmp_p2;

    delete[] G1;
    delete[] P1;


    // 8) 8 round
    int *G3 = new int[m * CONFIG_L / 8];
    int *P3 = new int[m * CONFIG_L / 8];

    tmp_g1 = new int[m * CONFIG_L / 8];
    tmp_g2 = new int[m * CONFIG_L / 8];
    tmp_p1 = new int[m * CONFIG_L / 8];
    tmp_p2 = new int[m * CONFIG_L / 8];
    for (int i = 0; i < m; i++) {
        for (int j = 1; j < CONFIG_L / 8; j++) {
            tmp_g1[i * CONFIG_L / 8 + j] = G2[i * CONFIG_L / 8 + 2 * j];
            tmp_g2[i * CONFIG_L / 8 + j] = G2[i * CONFIG_L / 8 + 2 * j - 1];
            tmp_p1[i * CONFIG_L / 8 + j] = P2[i * CONFIG_L / 8 + 2 * j];
            tmp_p2[i * CONFIG_L / 8 + j] = P2[i * CONFIG_L / 8 + 2 * j - 1];

        }
    }
    carry_calculation_server_batch(G3, P3, tmp_g1, tmp_p1, tmp_g2, tmp_p2, m * CONFIG_L / 8, tri_b, net);

    delete[] tmp_g1;
    delete[] tmp_g2;
    delete[] tmp_p1;
    delete[] tmp_p2;

    delete[] G2;
    delete[] P2;

    // 9) 4 round
    int *G4 = new int[m * CONFIG_L / 16];
    int *P4 = new int[m * CONFIG_L / 16];

    tmp_g1 = new int[m * CONFIG_L / 16];
    tmp_g2 = new int[m * CONFIG_L / 16];
    tmp_p1 = new int[m * CONFIG_L / 16];
    tmp_p2 = new int[m * CONFIG_L / 16];
    for (int i = 0; i < m; i++) {
        for (int j = 1; j < CONFIG_L / 16; j++) {
            tmp_g1[i * CONFIG_L / 16 + j] = G3[i * CONFIG_L / 16 + 2 * j];
            tmp_g2[i * CONFIG_L / 16 + j] = G3[i * CONFIG_L / 16 + 2 * j - 1];
            tmp_p1[i * CONFIG_L / 16 + j] = P3[i * CONFIG_L / 16 + 2 * j];
            tmp_p2[i * CONFIG_L / 16 + j] = P3[i * CONFIG_L / 16 + 2 * j - 1];
        }
    }
    carry_calculation_server_batch(G4, P4, tmp_g1, tmp_p1, tmp_g2, tmp_p2, m * CONFIG_L / 16, tri_b, net);

    delete[] tmp_g1;
    delete[] tmp_g2;
    delete[] tmp_p1;
    delete[] tmp_p2;

    delete[] G3;
    delete[] P3;

    // 10) 2 round
    int *G5 = new int[m * CONFIG_L / 32];
    int *P5 = new int[m * CONFIG_L / 32];

    tmp_g1 = new int[m * CONFIG_L / 32];
    tmp_g2 = new int[m * CONFIG_L / 32];
    tmp_p1 = new int[m * CONFIG_L / 32];
    tmp_p2 = new int[m * CONFIG_L / 32];
    for (int i = 0; i < m; i++) {
        for (int j = 1; j < CONFIG_L / 32; j++) {
            tmp_g1[i * CONFIG_L / 32 + j] = G4[i * CONFIG_L / 32 + 2 * j];
            tmp_g2[i * CONFIG_L / 32 + j] = G4[i * CONFIG_L / 32 + 2 * j - 1];
            tmp_p1[i * CONFIG_L / 32 + j] = P4[i * CONFIG_L / 32 + 2 * j];
            tmp_p2[i * CONFIG_L / 32 + j] = P4[i * CONFIG_L / 32 + 2 * j - 1];
        }
    }
    carry_calculation_server_batch(G5, P5, tmp_g1, tmp_p1, tmp_g2, tmp_p2, m * CONFIG_L / 32, tri_b, net);

    delete[] tmp_g1;
    delete[] tmp_g2;
    delete[] tmp_p1;
    delete[] tmp_p2;

    delete[] G4;
    delete[] P4;


    // 11)
    int *G60 = new int[m];
    int *G50 = new int[m];
    int *P51 = new int[m];
    for (int i = 0; i < m; i++) {
        G50[i] = G5[i * 2];
        P51[i] = P5[i * 2 + 1];
    }
    secure_mul_server_batch(G50, P51, G60, m, tri_b, net);
    for (int i = 0; i < m; i++) G60[i] += G5[i * 2 + 1];

//    delete[] G60;
    delete[] G50;
    delete[] P51;
    delete[] G5;
    delete[] P5;

    // 12)
    std::vector<mpz_class> v(m);
    for (int i = 0; i < m; i++) v[i] = G60[i] + bit(deltas[i], CONFIG_L - 1);

    delete[] G60;
}

void secure_inference_generation_server(int decision[], mpz_class value[], int depth, mpz_class result,
                                        const triplet_b &tri_b, const triplet_z &tri_z, NetAdapter *net) {
    unsigned long long num_of_node = (1 << depth) - 1;
    unsigned long long num_of_value = num_of_node + 1;

    // 1)
    // 2)

    int last_layer_node_count = 1 << (depth - 1);
    int *all_nodes = new int[last_layer_node_count * 2 * depth];
    int cur_layer = 0;
    for (int i = 0; i < depth; i++) {
        for (int j = 0; j < last_layer_node_count; j++) {
            int cur_layer = 1 << (i);
            int ratio = last_layer_node_count / cur_layer;

            all_nodes[i * 2 * last_layer_node_count + j * 2] = 1 - decision[cur_layer + j / ratio];
            all_nodes[i * 2 * last_layer_node_count + j * 2 + 1] = decision[cur_layer + j / ratio];
        }
    }
    int left_layer_count = depth / 2;
    while (left_layer_count > 1) {
        for (int i = 0; i < left_layer_count; i++) {
            secure_mul_server_batch(all_nodes + i * 2 * 2 * last_layer_node_count,
                                    all_nodes + (2 * i + 1) * 2 * last_layer_node_count,
                                    all_nodes + i * 2 * 2 * last_layer_node_count,
                                    last_layer_node_count * 2, tri_b, net);
        }

        left_layer_count /= 2;
    }


    int *G_2 = new int[num_of_value];
    memcpy(G_2, all_nodes, sizeof(int)*num_of_value);
    delete[] all_nodes;

    // 3)
    auto H1 = new int[num_of_value];
    auto H2 = new int[num_of_value];
    auto G = new int[num_of_value];
    auto tmp = new int[num_of_value];

    for (int z = 0; z < num_of_value; z++) {
        H1[z] = G_2[z];
        H2[z] = 0;
    }
    secure_mul_server_batch(H1, H2, tmp, num_of_value, tri_b, net);

    for (int z = 0; z < num_of_value; z++) {
        G[z] = H1[z] + H2[z] - 2 * tmp[z];
    }

    // 4)
    auto u_stars = new int[num_of_value];
    auto int_value = new int[num_of_value];
//    for (int i = 0; i < num_of_value; i++) int_value[i] = mpz_to_u64(value[i]);
    result = 0;
    secure_mul_server_batch(G, int_value, u_stars, num_of_value, tri_b, net);
    for (int z = 0; z < num_of_value; z++) {
        result += u_stars[z];
    }

    delete[] G_2;
    delete[] H1;
    delete[] H2;
    delete[] G;
    delete[] u_stars;
}