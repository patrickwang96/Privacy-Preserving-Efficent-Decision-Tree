/* main secure protocols used in the denoising */

#ifndef DENOISING_H
#define DENOISING_H

#include "types.h"
#include <vector>
#include "network.h"
#include <cryptoTools/Common/Defines.h>
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtReceiver.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtSender.h"


void secure_feature_selection_with_one_node(const matrix_z p[2], const matrix_z feature_share[2],
                                            mpz_class selected_feature[2], int index);

void secure_feature_selection_with_one_node_client(std::vector<uint64_t>& p, std::vector<uint64_t>& feature_share, uint64_t &selected_feature,
                                                   int index, NetAdapter *net, osuCrypto::KkrtNcoOtSender &sender, osuCrypto::KkrtNcoOtReceiver &receiver, osuCrypto::PRNG &prng, osuCrypto::Channel &chl);

void secure_feature_selection_with_one_node_server(std::vector<uint64_t>& p, std::vector<uint64_t> &feature_share, uint64_t &selected_feature,
                                                   int index, NetAdapter *net, osuCrypto::KkrtNcoOtSender &sender,osuCrypto::KkrtNcoOtReceiver &receiver, osuCrypto::PRNG &prng, osuCrypto::Channel &chl);

void secure_node_eval_with_look_ahead_carry_adder(mpz_class x[2], mpz_class y[2], const triplet_z &tri_z,
                                                  const triplet_b &tri_b);

void secure_node_eval_with_look_ahead_carry_adder_client(mpz_class x[], mpz_class y[], int m, const triplet_z &tri_z,
                                                         const triplet_b &tri_b, NetAdapter *net);

void secure_node_eval_with_look_ahead_carry_adder_server(mpz_class x[], mpz_class y[], int m, const triplet_z &tri_z,
                                                         const triplet_b &tri_b, NetAdapter *net);

void secure_inference_generation(int decision[][2], mpz_class value[][2], int depth, mpz_class result[2],
                                 const triplet_b &tri_b, const triplet_z &tri_z);

void secure_inference_generation_client(int decision[], mpz_class value[], int depth, mpz_class result,
                                        const triplet_b &tri_b, const triplet_z &tri_z, NetAdapter *net);

void secure_inference_generation_server(int decision[], mpz_class value[], int depth, mpz_class result,
                                        const triplet_b &tri_b, const triplet_z &tri_z, NetAdapter *net);

void secure_mul(int as[2], int bs[2], int ab_s[2], const triplet_b &tri);

void secure_mul(mpz_class as[2], mpz_class bs[2], mpz_class ab_s[2], const triplet_z &tri);

void secure_mul_client(mpz_class as, mpz_class bs, mpz_class &ab_s, const triplet_z &tri, NetAdapter *net);

void secure_mul_client(int as, int bs, int &ab_s, const triplet_b &tri, NetAdapter *net);

inline int bit(const mpz_class n, int k) { return n.get_ui() >> k & 1; }

void set_selection_index(matrix_z &sel_ind, int n);

#define SS_DO(expr) for(int i = 0; i < 2; i++) {expr}


inline void get_mpz_net(mpz_class &m, NetAdapter *net) {
    static uint64_t i;
    net->recv(reinterpret_cast<unsigned char *>(&(i)), sizeof(i));
    m = i;
}

inline void send_mpz_net(const mpz_class m, NetAdapter *net) {
    static uint64_t i;
    i = m.get_ui();
    net->send(reinterpret_cast<unsigned char *>(&i), sizeof(i));
}

inline void send_u64_net(uint64_t m, NetAdapter *net) {
    net->send(reinterpret_cast<unsigned char*> (&m), sizeof(m));
}

inline void get_u64_net(uint64_t &m, NetAdapter *net) {
    net->recv(reinterpret_cast<unsigned char *> (&m), sizeof(m));
}

inline uint64_t mpz_to_u64(mpz_class m){
    static size_t wordCount =0;
    return *static_cast<uint64_t*> (mpz_export(nullptr, &wordCount, 1, sizeof(uint64_t), 0, 0, m.get_mpz_t()));
}

inline uint64_t block_to_u64(osuCrypto::block m) {
    return _mm_cvtsi128_si64x(m);

}

#endif