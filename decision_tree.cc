#include "decision_tree.h"
#include "secret_sharing.h"

#include "utils.h"

#include <algorithm>
#include <vector>

extern gmp_randclass gmp_prn;

#define SS_DO(expr) \
    for(int i=0; i<2; ++i) {expr}

inline int bit(mpz_class n, int k) {
    return n.get_ui() >> k & 1;
}

void secure_mul(int as[2], int bs[2], int ab_s[2], const triplet_b &tri) {
    int e, es[2], f, fs[2];
    SS_DO(es[i] = mod_bit(as[i] - tri.us[i]);
                  fs[i] = mod_bit(bs[i] - tri.gs[i]);)

    ss_decrypt(e, es);
    ss_decrypt(f, fs);

    SS_DO(ab_s[i] = mod_bit(i * e * f + e * tri.gs[i] + f * tri.us[i] + tri.zs[i]);)
}

void secure_mul(mpz_class as[2], mpz_class bs[2], mpz_class ab_s[2], const triplet_z &tri) {
    mpz_class e, es[2], f, fs[2];
    SS_DO(es[i] = as[i] - tri.us[i];
                  mod_2exp(es[i], CONFIG_L);
                  fs[i] = bs[i] - tri.gs[i];
                  mod_2exp(fs[i], CONFIG_L);)

    ss_decrypt(e, es);
    ss_decrypt(f, fs);

    SS_DO(ab_s[i] = i * e * f + e * tri.gs[i] + f * tri.us[i] + tri.zs[i];
                  mod_2exp(ab_s[i], CONFIG_L);)
}

// ======= new
//extern gmp_randclass gmp_prn;
//#include "libOTe/Base/BaseOT.h"
//#include "libOTe/TwoChooseOne/KosOtExtSender.h"
//#include "libOTe/TwoChooseOne/KosOtExtReceiver.h"
//#include "libOTe/TwoChooseOne/IknpOtExtSender.h"
//#include "libOTe/TwoChooseOne/IknpOtExtReceiver.h"
//#include <cryptoTools/Common/Matrix.h>
//#include <cryptoTools/Common/BitVector.h>
//#include <cryptoTools/Network/Channel.h>

void secure_feature_selection_with_one_node(const matrix_z p[2],
                                            const matrix_z feature_share[2],
                                            mpz_class selected_feature[2], int index) {
    int feature_count = p[0].rows();
    std::vector<mpz_class> p_prime[2];
    mpz_class s[2], r[2];

    SS_DO(s[i] = gmp_prn.get_z_bits(CONFIG_L);
                  r[i] = gmp_prn.get_z_bits(CONFIG_L);
                  p_prime[i].reserve(feature_count);)

    // 1)
    for (int j = 0; j < feature_count; j++) {
        static mpz_class j_star;
        SS_DO(
                j_star = j + s[i];
                mod_2exp(j_star, CONFIG_L);
                j_star %= feature_count;
                p_prime[i][j] = p[i](j_star.get_ui(), i) + r[i];)
    }

    // 2)
    mpz_class random[2];
    SS_DO(random[i] = gmp_prn.get_z_bits(CONFIG_L);)
    static mpz_class i_prime = feature_share[0](index, 0) + random[0];

    // 3)
    static mpz_class i_origin_with_mask = i_prime + feature_share[1](index, 0) + s[1];

    // 4)
    static mpz_class i_origin_prime = i_origin_with_mask - random[0];
    mod_2exp(i_origin_prime, CONFIG_L);
    i_origin_prime %= feature_count;

    // 5)
    // TODO
//     1-n OT
//        PRNG prng(sysRandomSeed());
//        IknpOtExtReceiver recver;

    // Choose which messages should be received.
//        BitVector choices(feature_count);
//        choices[i_origin_prime.get_ui()] = 1;

    // Receive the messages
//        std::vector<block> messages(n);
//        recver.receiveChosen(choices, messages, prng, recverChl);

    // 6)
    mpz_class p_selected_prime[2];

    // 7)
    mpz_class random_prime[2];
    SS_DO(random_prime[i] = gmp_prn.get_z_bits(CONFIG_L);)
    p_selected_prime[0] = p_selected_prime[0] - random[1] - random_prime[1];

    // 8)
    p_selected_prime[0] = p_selected_prime[0] + p_selected_prime[1] - random[0];
}

inline void
carry_calculation(int G_star[2], int P_star[2], int G1[2], int P1[2], int G2[2], int P2[2], const triplet_b &tri_b) {
    int gp[2], pp[2];
    secure_mul(G2, P1, gp, tri_b);
    secure_mul(P1, P2, pp, tri_b);
    SS_DO(G_star[i] = G1[i] + gp[i];
                  P_star[i] = pp[i];)
}

void secure_node_eval_with_look_ahead_carry_adder(mpz_class x[2], mpz_class y[2], const triplet_z &tri_z,
                                                  const triplet_b &tri_b) {

    mpz_class delta[2];

    // 1) compute delta over secrete shares
    SS_DO(delta[i] = y[i] - x[i];
                  mod_2exp(delta[i], CONFIG_L);)

    // 3, 4) setup round for secure carry computation
//    int (*G)[2] = new int[CONFIG_L][2];
//    int (*P)[2] = new int[CONFIG_L][2];
    int G[CONFIG_L][2], P[CONFIG_L][2];
    int a_q[2], b_q[2];
    a_q[1] = 0;
    b_q[0] = 0;

    for (int i = 0; i < CONFIG_L; i++) {
        a_q[0] = bit(delta[0], i);
        b_q[1] = bit(delta[1], i);
        secure_mul(a_q, b_q, G[i], tri_b);
        P[i][0] = a_q[0];
        P[i][1] = b_q[1];
    }

    // 5)
    int G1[CONFIG_L / 2][2], P1[CONFIG_L / 2][2];
    SS_DO(G1[0][i] = G[0][i]; P1[0][i] = P[0][i];)

    // 6) 32 round
    for (int i = 1; i < CONFIG_L / 2; i++) {
        carry_calculation(G1[i], P1[i], G[2 * i], P[2 * i], G[2 * i - 1], P[2 * i - 1], tri_b);
    }

    // 7) 16 round
    int G2[CONFIG_L / 4][2], P2[CONFIG_L / 4][2];
    for (int i = 0; i < CONFIG_L / 4; i++) {
        carry_calculation(G2[i], P2[i], G1[2 * i + 1], P1[2 * i + 1], G1[2 * i], P1[2 * i], tri_b);
    }

    // 8) 8 round
    int G3[CONFIG_L / 8][2], P3[CONFIG_L / 8][2];
    for (int i = 0; i < CONFIG_L / 8; i++) {
        carry_calculation(G3[i], P3[i], G2[2 * i + 1], P2[2 * i + 1], G2[2 * i], P2[2 * i], tri_b);
    }

    // 9) 4 round
    int G4[CONFIG_L / 16][2], P4[CONFIG_L / 16][2];
    for (int i = 0; i < CONFIG_L / 16; i++) {
        carry_calculation(G4[i], P4[i], G3[2 * i + 1], P3[2 * i + 1], G3[2 * i], P3[2 * i], tri_b);
    }

    // 10) 2 round
    int G5[CONFIG_L / 32][2], P5[CONFIG_L / 32][2];
    for (int i = 0; i < CONFIG_L / 32; i++) {
        carry_calculation(G5[i], P5[i], G4[2 * i + 1], P4[2 * i + 1], G4[2 * i], P4[2 * i], tri_b);
    }

    // 11)
    int G60[2];
    secure_mul(G5[0], P5[1], G60, tri_b);
    SS_DO(G60[i] += G5[1][i];)

    // 12)
    mpz_class v[2];
    SS_DO(v[i] = G60[i] + bit(delta[i], CONFIG_L - 1);)

}

void secure_inference_generation(int decision[][2], mpz_class value[][2], int depth, mpz_class result[2],
                                 const triplet_b &tri_b, const triplet_z &tri_z) {
    unsigned long long num_of_edge = (1 << depth) - 1;
    unsigned long long num_of_value = num_of_edge + 1;

    // 1)
    auto E_L = new int[num_of_edge][2];
    auto E_R = new int[num_of_edge][2];

    for (int j = 0; j < num_of_edge; j++) {
        E_L[j][0] = 1 - decision[j][0];
        E_L[j][1] = decision[j][1];
        SS_DO(E_R[j][i] = decision[j][i];)
    }

    // 2)
    auto G_2 = new int[num_of_value][2];
    int cur_node = 0;
    for (int d = 0; d < depth; d++) {
        int num_layer_node = 1 << d;
        for (int node = 0; node < num_layer_node; node++) {
            // TODO
        }

    }

    // 3)
    auto H1 = new mpz_class[num_of_value][2];
    auto H2 = new mpz_class[num_of_value][2];
    auto G = new mpz_class[num_of_value][2];
    auto tmp = new mpz_class[2];
    for (int z = 0; z < num_of_value; z++) {
        // a)
        H1[z][0] = G_2[z][0];
        H1[z][1] = 0;
        H2[z][0] = 0;
        H2[z][1] = G_2[z][1];
        secure_mul(H1[z], H2[z], tmp, tri_z);

        // b)
        SS_DO(G[z][i] = H1[z][i] + H2[z][i] - 2 * tmp[i];)
    }


    // 4)
    auto u_stars = new mpz_class[num_of_value][2];
    SS_DO(result[i] = 0;)
    for (int z = 0; z < num_of_value; z++) {
        secure_mul(G[z], value[z], u_stars[z], tri_z);
        SS_DO(result[i] += u_stars[z][i];)
    }

    delete[] E_L;
    delete[] E_R;
    delete[] G_2;
    delete[] H1;
    delete[] H2;
    delete[] G;
    delete[] tmp;
    delete[] u_stars;
}