/* main secure protocols used in the denoising */

#ifndef DENOISING_H
#define DENOISING_H

#include "types.h"
#include <vector>

void secure_multiplication(const matrix_z shareA[2], const matrix_z shareB[2], 
						  const triplet_mz shareTri[2],
						  // intermediate buffers
						  ss_tuple_mz &U, ss_tuple_mz &V, 
						  // output
						  matrix_z shareAB[2],
						  // whether to conduct piecewise multiplication
						  int piecewise);

void secure_node_evaluation(mpz_class x[2], mpz_class y[2], const triplet_z& tri_z, const triplet_b& tri_b);

void secure_class_generation_path_cost(const std::vector<mpz_class>& edges, std::vector<mpz_class>& leaf_value, std::vector<mpz_class>& interm_rlt, std::vector<mpz_class>& path_cost, int depth);

void secure_class_generation_polynomial(mpz_class (*edges)[2], mpz_class (*leaf_value)[2], mpz_class (*interm_rlt)[2], mpz_class (*path_mul)[2], const triplet_z& tri, int depth);

#endif