#include "secret_sharing_efficient_tools.h"

inline uint8_t zip_to_one_byte(uint8_t *raw, int m) {
    // raw has to been a array of len 8, m <= 8
    uint8_t result = 0;
    if (m > 8) m = 8;
    for (int i = 0; i < m; i++) result &= (raw[i] << (7 - i));

    return result;
}

inline void unzip_to_one_byte(uint8_t ziped, int m, uint8_t *output) {
    // m <= 8;
    if (m > 8) m = 8;
    for (int i = 0; i < m; i++) output[i] = (ziped >> (7 - i));
}

inline int zip_to_one_int(int *raw, int m) {
    // raw has to been a array of len 8, m <= 8
    int result = 0;
    if (m > 32) m = 32;
    for (int i = 0; i < m; i++) result &= (raw[i] << (31 - i));

    return result;
}

inline void unzip_to_one_int(uint8_t ziped, int m, int *output) {
    // m <= 8;
    if (m > 32) m = 32;
    for (int i = 0; i < m; i++) output[i] = (ziped >> (31 - i));
}

uint8_t *bit_compression(uint8_t *input, int m, int &n) {
    if (m % 8 == 0) n = m / 8;
    else n = m / 8 + 1;
    int chunk_size;

    uint8_t *output = new uint8_t[n];
    for (int i = 0; i < n; i++) {
        chunk_size = std::min(8, m);
        output[i] = zip_to_one_byte(input + 8 * i, chunk_size);
        m -= chunk_size;
    }
    return output;
}

uint8_t *bit_decompression(uint8_t *input, int m, int n) {
    uint8_t *output = new uint8_t[m];
    int chunk_size;
    for (int i = 0; i < n; i++) {
        chunk_size = std::min(8, m);
        unzip_to_one_byte(input[i], chunk_size, output + i * 8);
        m -= chunk_size;
    }
    return output;
}

int *bit_compression(int *input, int m, int &n) {
    if (m % 32 == 0) n = m / 32;
    else n = m / 32 + 1;
    int chunk_size;

    int *output = new int[n];
    for (int i = 0; i < n; i++) {
        chunk_size = std::min(32, m);
        output[i] = zip_to_one_int(input + 32 * i, chunk_size);
        m -= chunk_size;
    }
    return output;
}

void bit_decompression(int *input, int *output, int m, int n) {
//	int * output = new int[m];
    int chunk_size;
    for (int i = 0; i < n; i++) {
        chunk_size = std::min(32, m);
        unzip_to_one_int(input[i], chunk_size, output + i * 32);
        m -= chunk_size;
    }
//	return output;
}