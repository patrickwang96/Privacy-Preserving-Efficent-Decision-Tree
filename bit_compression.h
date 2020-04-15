#ifndef PRIVACY_PRESERVING_EFFICENT_DECISION_TREE_COMPRESSON_H
#define PRIVACY_PRESERVING_EFFICENT_DECISION_TREE_COMPRESSON_H

#include <algorithm>

uint8_t* bit_compression(uint8_t * input, int m, int &n) ;

uint8_t* bit_decompression(uint8_t* input, int m, int n) ;

int* bit_compression(int * input, int m, int &n);

int* bit_decompression(int* input, int m, int n);

#endif //PRIVACY_PRESERVING_EFFICENT_DECISION_TREE_COMPRESSON_H