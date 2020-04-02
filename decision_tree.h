/* main secure protocols used in the denoising */

#ifndef DENOISING_H
#define DENOISING_H

#include "types.h"
#include <vector>
#include "network.h"


void secure_feature_selection_with_one_node(const matrix_z p[2], const matrix_z feature_share[2], mpz_class selected_feature[2], int index);

void secure_feature_selection_with_one_node_client(const matrix_z p[2], const matrix_z feature_share[2], mpz_class selected_feature[2], int index, NetAdapter *net);

void secure_feature_selection_with_one_node_server(const matrix_z p[2], const matrix_z feature_share[2], mpz_class selected_feature[2], int index, NetAdapter *net);

void secure_node_eval_with_look_ahead_carry_adder(mpz_class x[2], mpz_class y[2], const triplet_z & tri_z, const triplet_b& tri_b);

void secure_node_eval_with_look_ahead_carry_adder_client(mpz_class x, mpz_class y, const triplet_z & tri_z, const triplet_b& tri_b, NetAdapter *net);

void secure_node_eval_with_look_ahead_carry_adder_server(mpz_class x, mpz_class y, const triplet_z & tri_z, const triplet_b& tri_b, NetAdapter *net);

void secure_inference_generation(int decision[][2], mpz_class value[][2], int depth, mpz_class result[2], const triplet_b& tri_b, const triplet_z& tri_z);

void secure_inference_generation_client(int decision[][2], mpz_class value[][2], int depth, mpz_class result[2], const triplet_b& tri_b, const triplet_z& tri_z, NetAdapter *net);

void secure_inference_generation_server(int decision[][2], mpz_class value[][2], int depth, mpz_class result[2], const triplet_b& tri_b, const triplet_z& tri_z, NetAdapter *net);

#endif