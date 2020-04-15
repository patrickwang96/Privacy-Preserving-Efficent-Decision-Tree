//
// Created by patrickwang on 15/4/2020.
//

#ifndef PRIVACY_PRESERVING_EFFICENT_DECISION_TREE_SECRET_SHARING_EFFICIENT_TOOLS_H
#define PRIVACY_PRESERVING_EFFICENT_DECISION_TREE_SECRET_SHARING_EFFICIENT_TOOLS_H

#include "network.h"
#include "secret_sharing.h"
#include <vector>
#include "cryptoTools/Crypto/PRNG.h"
#include "decision_tree.h"
#include "utils.h"
#include <algorithm>
#include <cstdint>

void ss_decrypt_server(int &plain, int share, NetAdapter *net);


void ss_decrypt_server_batch(int plain[], int share[], int m, NetAdapter *net);

void secure_mul_server(int as, int bs, int &ab_s, const triplet_b &tri, NetAdapter *net);

void secure_mul_server_batch(int as[], int bs[], int ab_s[], int m, const triplet_b &tri, NetAdapter *net);

void secure_mul_server_batch(mpz_class as[], mpz_class bs[], mpz_class ab_s[], int m, const triplet_b &tri,
                             NetAdapter *net);


void ss_decrypt_server(mpz_class &plain, mpz_class share, NetAdapter *net);


void secure_mul_server(mpz_class as, mpz_class bs, mpz_class &ab_s, const triplet_z &tri, NetAdapter *net);

uint64_t secure_feature_index_sharing_server(uint64_t index, uint64_t feature_count, uint64_t random,
                                             std::vector<uint64_t> &feature_share, NetAdapter *net);

void
secure_feature_index_sharing_client(uint64_t index, uint64_t s, std::vector<uint64_t> &feature_share, NetAdapter *net);

void secure_feature_index_sharing_client_batch(uint64_t s, std::vector<uint64_t> &feature_share, NetAdapter *net);

void secure_feature_index_sharing_server_batch(uint64_t *i_origin, uint64_t feature_count, osuCrypto::PRNG &prng,
                                               std::vector<uint64_t> &feature_share,
                                               NetAdapter *net);

void ss_decrypt_client(int &plain, int share, NetAdapter *net);

void ss_decrypt_client(mpz_class &plain, mpz_class share, NetAdapter *net);

void ss_decrypt_client_batch(int plain[], int share[], int m, NetAdapter *net);


void secure_mul_client(int as, int bs, int &ab_s, const triplet_b &tri, NetAdapter *net);

void secure_mul_client(mpz_class as, mpz_class bs, mpz_class &ab_s, const triplet_z &tri, NetAdapter *net);

void secure_mul_client_batch(int as[], int bs[], int ab_s[], int m, const triplet_b &tri, NetAdapter *net);

void secure_mul_client_batch(mpz_class as[], mpz_class bs[], mpz_class ab_s[], int m, const triplet_b &tri,
                             NetAdapter *net);


uint8_t* bit_compression(uint8_t * input, int m, int &n) ;

uint8_t* bit_decompression(uint8_t* input, int m, int n) ;

int* bit_compression(int * input, int m, int &n);

int* bit_decompression(int* input, int m, int n);

#endif //PRIVACY_PRESERVING_EFFICENT_DECISION_TREE_SECRET_SHARING_EFFICIENT_TOOLS_H
