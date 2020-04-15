//
// Created by patrickwang on 15/4/2020.
//

#include "secret_sharing_efficient_tools.h"

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

void ss_decrypt_server_batch_compressed(int plain[], int share[], int m, NetAdapter *net) {
    int *recv_share = new int[m];
    int n;
    if (m % 32 == 0) n = m / 32;
    else n = m / 32 + 1;
    int* zipped_recv_share = new int[n];
    net->recv(reinterpret_cast<unsigned char *> (zipped_recv_share), sizeof(int) * n);
    bit_decompression(zipped_recv_share, recv_share, m, n);
    for (int i = 0; i < m; i++)
        plain[i] = mod_bit(share[i] + recv_share[i]);

    int* zipped_plain = bit_compression(plain, m, n);
    net->send(reinterpret_cast<unsigned char *>(zipped_plain), sizeof(int) * n);
    delete[] recv_share;
    delete[] zipped_plain;
    delete[] zipped_recv_share;

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

void secure_mul_server_batch_compressed(int as[], int bs[], int ab_s[], int m, const triplet_b &tri, NetAdapter *net) {
    int *e = new int[m];
    int *es = new int[m];
    int *f = new int[m];
    int *fs = new int[m];

    for (int i = 0; i < m; i++) {
        es[i] = mod_bit(as[i] - tri.us[0]);
        fs[i] = mod_bit(bs[i] - tri.gs[0]);
    }
    ss_decrypt_server_batch_compressed(e, es, m, net);
    ss_decrypt_server_batch_compressed(f, fs, m, net);

    for (int i = 0; i < m; i++) {
        ab_s[i] = mod_bit(0 * e[i] * f[i] + e[i] * tri.gs[0] + f[i] * tri.us[0] + tri.zs[0]);
    }
    delete[] e;
    delete[] es;
    delete[] f;
    delete[] fs;
}

void secure_mul_server_batch(mpz_class as[], mpz_class bs[], mpz_class ab_s[], int m, const triplet_b &tri,
                             NetAdapter *net) {
    int *as_int = new int[m];
    int *bs_int = new int[m];
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

uint64_t secure_feature_index_sharing_server(uint64_t index, uint64_t feature_count, uint64_t random,
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

void
secure_feature_index_sharing_client(uint64_t index, uint64_t s, std::vector<uint64_t> &feature_share, NetAdapter *net) {
    // 2)
    static uint64_t i_prime;
    get_u64_net(i_prime, net);
    // 3)
    static uint64_t i_origin_with_mask = i_prime + feature_share[index] + s;
    send_u64_net(i_origin_with_mask, net);

}

void secure_feature_index_sharing_client_batch(uint64_t s, std::vector<uint64_t> &feature_share, NetAdapter *net) {
    int index_range = feature_share.size();
    uint64_t *i_primes = new uint64_t[index_range];
    uint64_t *i_origin_with_mask = new uint64_t[index_range];
    net->recv(reinterpret_cast<unsigned char *>(i_primes), sizeof(uint64_t) * index_range);
    for (int i = 0; i < index_range; i++) i_origin_with_mask[i] = i_primes[i] + feature_share[i] + s;
    net->send(reinterpret_cast<unsigned char *>(i_origin_with_mask), sizeof(uint64_t) * index_range);
    delete[] i_origin_with_mask;
    delete[] i_primes;
}

void secure_feature_index_sharing_server_batch(uint64_t *i_origin, uint64_t feature_count, PRNG &prng,
                                               std::vector<uint64_t> &feature_share,
                                               NetAdapter *net) {
    int index_range = feature_share.size();
    uint64_t *i_primes = new uint64_t[index_range];
    uint64_t *i_origin_with_mask = new uint64_t[index_range];
    uint64_t *randoms = new uint64_t[index_range];
    for (int i = 0; i < index_range; i++) {
        randoms[i] = prng.get<uint64_t>();
        i_primes[i] = feature_share[i] + randoms[i];
    }
    net->send(reinterpret_cast<unsigned char *> (i_primes), sizeof(uint64_t) * index_range);
    net->recv(reinterpret_cast<unsigned char *> (i_origin_with_mask), sizeof(uint64_t) * index_range);

    for (int i = 0; i < index_range; i++) {
        i_origin[i] = i_origin_with_mask[i] - randoms[i];
        i_origin[i] %= feature_count;
    }
    delete[] i_primes;
    delete[] i_origin_with_mask;
    delete[] randoms;
}

void ss_decrypt_client(int &plain, int share, NetAdapter *net) {
    // client send the int share first, then the server send back;
    net->send(reinterpret_cast<unsigned char *>(&share), sizeof(share));
    net->recv(reinterpret_cast<unsigned char *>(&plain), sizeof(share));
//    plain = mod_bit(share[0] + share[1]);
}

void ss_decrypt_client_batch(int plain[], int share[], int m, NetAdapter *net) {
    net->send(reinterpret_cast<unsigned char *>(share), sizeof(int) * m);
    net->recv(reinterpret_cast<unsigned char *>(plain), sizeof(int) * m);
}

void ss_decrypt_client_batch_compressed(int plain[], int share[], int m, NetAdapter *net) {
    int n = m;
    int *zipped_share = bit_compression(share, m, n);
    int *zipped_plain = new int[n];
    net->send(reinterpret_cast<unsigned char *>(zipped_share), sizeof(int) * n);

    net->recv(reinterpret_cast<unsigned char *>(zipped_plain), sizeof(int) * n);
    bit_decompression(zipped_plain, plain, m, n);
    delete[] zipped_plain;
    delete[] zipped_share;
}

void secure_mul_client(int as, int bs, int &ab_s, const triplet_b &tri, NetAdapter *net) {
    int e, es, f, fs;
    es = mod_bit(as - tri.us[1]);
    fs = mod_bit(bs - tri.gs[1]);

    ss_decrypt_client(e, es, net);
    ss_decrypt_client(f, fs, net);

    ab_s = mod_bit(1 * e * f + e * tri.gs[1] + f * tri.us[1] + tri.zs[1]);
}

void secure_mul_client_batch(int as[], int bs[], int ab_s[], int m, const triplet_b &tri, NetAdapter *net) {
    int *e = new int[m];
    int *es = new int[m];
    int *f = new int[m];
    int *fs = new int[m];

    for (int i = 0; i < m; i++) {
        es[i] = mod_bit(as[i] - tri.us[1]);
        fs[i] = mod_bit(bs[i] - tri.gs[1]);
    }
    ss_decrypt_client_batch(e, es, m, net);
    ss_decrypt_client_batch(f, fs, m, net);

    for (int i = 0; i < m; i++) {
        ab_s[i] = mod_bit(1 * e[i] * f[i] + e[i] * tri.gs[1] + f[i] * tri.us[1] + tri.zs[1]);
    }
    delete[] e;
    delete[] es;
    delete[] f;
    delete[] fs;
}

void secure_mul_client_batch_compressed(int as[], int bs[], int ab_s[], int m, const triplet_b &tri, NetAdapter *net) {
    int *e = new int[m];
    int *es = new int[m];
    int *f = new int[m];
    int *fs = new int[m];

    for (int i = 0; i < m; i++) {
        es[i] = mod_bit(as[i] - tri.us[1]);
        fs[i] = mod_bit(bs[i] - tri.gs[1]);
    }
    ss_decrypt_client_batch_compressed(e, es, m, net);
    ss_decrypt_client_batch_compressed(f, fs, m, net);

    for (int i = 0; i < m; i++) {
        ab_s[i] = mod_bit(1 * e[i] * f[i] + e[i] * tri.gs[1] + f[i] * tri.us[1] + tri.zs[1]);
    }
    delete[] e;
    delete[] es;
    delete[] f;
    delete[] fs;
}

void secure_mul_client_batch(mpz_class as[], mpz_class bs[], mpz_class ab_s[], int m, const triplet_b &tri,
                             NetAdapter *net) {
    int *as_int = new int[m];
    int *bs_int = new int[m];
    int *ab_s_int = new int[m];
    for (int i = 0; i < m; i++) {
        as_int[i] = mpz_to_u64(as[i]);
        bs_int[i] = mpz_to_u64(bs[i]);
    }
    secure_mul_client_batch(as_int, bs_int, ab_s_int, m, tri, net);
    for (int i = 0; i < m; i++) {
        ab_s[i] = ab_s_int[i];
    }

}

void ss_decrypt_client(mpz_class &plain, mpz_class share, NetAdapter *net) {
    // client send the int share first, then the server send back;
    send_mpz_net(share, net);
    get_mpz_net(plain, net);
}

void secure_mul_client(mpz_class as, mpz_class bs, mpz_class &ab_s, const triplet_z &tri, NetAdapter *net) {
    mpz_class e, es, f, fs;
    es = as - tri.us[1];
    mod_2exp(es, CONFIG_L);
    fs = bs - tri.gs[1];
    mod_2exp(fs, CONFIG_L);

    ss_decrypt_client(e, es, net);
    ss_decrypt_client(f, fs, net);

    ab_s = 1 * e * f + e * tri.gs[1] + f * tri.us[1] + tri.zs[1];
    mod_2exp(ab_s, CONFIG_L);
}
