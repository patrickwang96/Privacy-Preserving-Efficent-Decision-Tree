#ifndef SECRET_SHARING_H
#define SECRET_SHARING_H

#include "types.h"

// ring Z_2
void ss_encrypt(int plain, int share[2]);
void ss_decrypt(int &plain, int share[2]);

// ring Z_2^l
void ss_encrypt(const mpz_class &plain, mpz_class share[2]);
void ss_decrypt(mpz_class &plain, const mpz_class share[2]);

// matrix
void ss_encrypt(const matrix_z &plain, matrix_z &share0, matrix_z &share1);
void ss_decrypt(matrix_z &plain, const matrix_z &share0, const matrix_z &share1);

void ss_encrypt(const matrix_z &plain, matrix_z share[2]);
void ss_decrypt(matrix_z &plain, const matrix_z share[2]);
#endif