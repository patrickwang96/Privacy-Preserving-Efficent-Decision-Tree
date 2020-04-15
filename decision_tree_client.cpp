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
#include "secret_sharing_efficient_tools.h"

using namespace osuCrypto;
extern gmp_randclass gmp_prn;


void secure_feature_selection_with_one_node_client(std::vector<uint64_t> &p, std::vector<uint64_t> &feature_share,
                                                   uint64_t &selected_feature, int index, NetAdapter *net,
                                                   KkrtNcoOtSender &sender, KkrtNcoOtReceiver &receiver, PRNG &prng,
                                                   Channel &chl) {

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
    secure_feature_index_sharing_client_batch(s, feature_share, net);

    // 5)
    // client C1 acts like a sender
    Matrix<block> otMat(m, feature_count);
    for (int j = 0; j < m; j++)
        for (int i = 0; i < feature_count; i++) {
            otMat[j][i] = toBlock(p_prime[i]);
        }
    sender.sendChosen(otMat, prng, chl);

    // 6)
    uint64_t random;

    uint64_t *i_origin_primes = new uint64_t[m];
    secure_feature_index_sharing_server_batch(i_origin_primes, feature_count, prng, feature_share, net);
    std::vector<block> recvMsgs(m);
    std::vector<uint64_t> choices(m);
    for (int i = 0; i < m; i++) choices[i] = i_origin_primes[i];
    receiver.receiveChosen(feature_count, recvMsgs, choices, prng, chl);

    delete[] i_origin_primes;

    std::vector<uint64_t> p_prime_0(m);
    for (int i = 0; i < m; i++) {
        p_prime_0[i] = block_to_u64(recvMsgs[i]);
    }

    // 7)
    uint64_t random_prime;
//    std::vector<uint64_t> p_stars(m);
    uint64_t *p_stars = new uint64_t[m];
    for (int i = 0; i < m; i++) {
        random_prime = prng.get<uint64_t>();

        p_stars[i] = p_prime_0[i] - r - random_prime;
//        send_u64_net(p_stars[i], net);
    }
    net->send(reinterpret_cast<unsigned char *>(p_stars), sizeof(uint64_t) * m);


    net->recv(reinterpret_cast<unsigned char *>(p_stars), sizeof(uint64_t) * m);
    for (int i = 0; i < m; i++) {
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

void carry_calculation_client_batch(int G_star[], int P_star[], int G1[], int P1[], int G2[], int P2[], int m,
                                    const triplet_b &tri_b, NetAdapter *net) {
    int *gp = new int[m];
    int *pp = new int[m];
    secure_mul_client_batch(G2, P1, gp, m, tri_b, net);
    secure_mul_client_batch(P1, P2, pp, m, tri_b, net);
    for (int i = 0; i < m; i++) {
        G_star[i] = G1[i] + gp[i];
        P_star[i] = pp[i];
    }
    delete[] gp;
    delete[] pp;
}
void carry_calculation_client_batch_compressed(int G_star[], int P_star[], int G1[], int P1[], int G2[], int P2[], int m,
                                    const triplet_b &tri_b, NetAdapter *net) {
    int *gp = new int[m];
    int *pp = new int[m];
    secure_mul_client_batch_compressed(G2, P1, gp, m, tri_b, net);
    secure_mul_client_batch_compressed(P1, P2, pp, m, tri_b, net);
    for (int i = 0; i < m; i++) {
        G_star[i] = G1[i] + gp[i];
        P_star[i] = pp[i];
    }
    delete[] gp;
    delete[] pp;
}

void secure_node_eval_with_look_ahead_carry_adder_client(mpz_class x[], mpz_class y[], int m,
                                                         const triplet_z &tri_z,
                                                         const triplet_b &tri_b, NetAdapter *net) {

    mpz_class delta;
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
    secure_mul_client_batch_compressed(a_q, b_q, G, m * CONFIG_L, tri_b, net);
    memcpy(P, a_q, sizeof(int) * m * CONFIG_L);

    // 5)
    const int total_count = m * CONFIG_L;
    int *G1 = new int[total_count / 2];
    int *P1 = new int[total_count / 2];
    for (int i = 0; i < m; i++) {
        G1[i * CONFIG_L / 2] = G[i * CONFIG_L];
        P1[i * CONFIG_L / 2] = P[i * CONFIG_L];
    }

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
    carry_calculation_client_batch_compressed(G1, P1, tmp_g1, tmp_p1, tmp_g2, tmp_p2, m * CONFIG_L / 2, tri_b, net);

    delete[] tmp_g1;
    delete[] tmp_g2;
    delete[] tmp_p1;
    delete[] tmp_p2;

    delete[] G;
    delete[] P;

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
    carry_calculation_client_batch_compressed(G2, P2, tmp_g1, tmp_p1, tmp_g2, tmp_p2, m * CONFIG_L / 4, tri_b, net);

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
    carry_calculation_client_batch_compressed(G3, P3, tmp_g1, tmp_p1, tmp_g2, tmp_p2, m * CONFIG_L / 8, tri_b, net);

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
    carry_calculation_client_batch_compressed(G4, P4, tmp_g1, tmp_p1, tmp_g2, tmp_p2, m * CONFIG_L / 16, tri_b, net);

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
    carry_calculation_client_batch_compressed(G5, P5, tmp_g1, tmp_p1, tmp_g2, tmp_p2, m * CONFIG_L / 32, tri_b, net);

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
    secure_mul_client_batch_compressed(G50, P51, G60, m, tri_b, net);
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

void secure_inference_generation_client(int decision[], mpz_class value[], int depth, mpz_class result,
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
            secure_mul_client_batch_compressed(all_nodes + i * 2 * 2 * last_layer_node_count,
                                    all_nodes + (2 * i + 1) * 2 * last_layer_node_count,
                                    all_nodes + i * 2 * 2 * last_layer_node_count,
                                    last_layer_node_count * 2, tri_b, net);
        }

        left_layer_count /= 2;
    }


    int *G_2 = new int[num_of_value];
    memcpy(G_2, all_nodes, sizeof(int) * num_of_value);
    delete[] all_nodes;

    // 3)
    auto H1 = new uint64_t[num_of_value];
    auto H2 = new uint64_t[num_of_value];
    auto G = new uint64_t[num_of_value];
    auto tmp = new uint64_t[num_of_value];

    for (int z = 0; z < num_of_value; z++) {
        H1[z] = G_2[z];
        H2[z] = 0;
    }
    secure_mul_client_batch(H1, H2, tmp, num_of_value, tri_b, net);

    for (int z = 0; z < num_of_value; z++) {
        G[z] = H1[z] + H2[z] - 2 * tmp[z];
    }

    // 4)
    auto u_stars = new uint64_t[num_of_value];
    auto int_value = new uint64_t[num_of_value];
//    for (int i = 0; i < num_of_value; i++) int_value[i] = mpz_to_u64(value[i]);
    result = 0;
    uint64_t counter = 0;
    secure_mul_client_batch(G, int_value, u_stars, num_of_value, tri_b, net);
    for (int z = 0; z < num_of_value; z++) {
        counter += u_stars[z];
    }
//    result = counter;

    delete[] G_2;
    delete[] H1;
    delete[] H2;
    delete[] G;
    delete[] u_stars;
}