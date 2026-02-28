// Reed-Solomon erasure coding over GF(2^8). Vendored implementation;
// no external dependencies. Primitive polynomial 0x11D (x^8 + x^4 + x^3 + x^2 + 1).
// Systematic encoding using a Vandermonde-style matrix so any k of n shards recover data.

#include "reed_solomon.h"
#include <algorithm>
#include <cassert>
#include <vector>

namespace reed_solomon {

namespace {

const unsigned GF_SIZE = 256;
const uint8_t PRIMITIVE = 0x1d;  // 0x11D polynomial, high bit implied

// exp[i] = alpha^i in GF(2^8), log[x] = i such that exp[i] = x (log[0] unused).
uint8_t g_exp[GF_SIZE * 2];  // doubled for easy mod-free mul
uint8_t g_log[GF_SIZE];

void init_galois() {
  uint8_t x = 1;
  for (unsigned i = 0; i < 255; ++i) {
    g_exp[i] = x;
    g_exp[i + 255] = x;
    g_log[x] = static_cast<uint8_t>(i);
    x = (x << 1) ^ (x & 0x80 ? PRIMITIVE : 0);
  }
  g_log[0] = 0;  // sentinel; never use 0 as multiplier
}

bool galois_initialized = false;

void ensure_galois() {
  if (!galois_initialized) {
    init_galois();
    galois_initialized = true;
  }
}

inline uint8_t galois_mul(uint8_t a, uint8_t b) {
  if (a == 0 || b == 0) return 0;
  return g_exp[g_log[a] + g_log[b]];
}

inline uint8_t galois_div(uint8_t a, uint8_t b) {
  if (b == 0) return 0;
  if (a == 0) return 0;
  return g_exp[g_log[a] + 255 - g_log[b]];
}

// Generator row for parity index r (r in 0..m-1): G[r][j] = alpha^(r*j).
// Data rows 0..k-1 are identity; parity rows are these.
inline uint8_t gen_coeff(unsigned parity_row, unsigned j) {
  return g_exp[(parity_row * j) % 255];
}

// Build row i of generator (n x k): identity for i < k, else parity row i-k.
inline uint8_t generator_coeff(unsigned /*n*/, unsigned k, unsigned row, unsigned col) {
  if (row < k)
    return (row == col) ? 1 : 0;
  return gen_coeff(row - k, col);
}

// In-place invert square matrix M (size x size) over GF(2^8). Returns true on success.
bool matrix_invert(uint8_t* M, unsigned size) {
  std::vector<uint8_t> inv(size * size);
  for (unsigned i = 0; i < size; ++i)
    inv[i * size + i] = 1;

  for (unsigned col = 0; col < size; ++col) {
    // Find pivot in column col
    unsigned pivot = col;
    while (pivot < size && M[pivot * size + col] == 0) ++pivot;
    if (pivot == size) return false;
    if (pivot != col) {
      for (unsigned j = 0; j < size; ++j) {
        std::swap(M[col * size + j], M[pivot * size + j]);
        std::swap(inv[col * size + j], inv[pivot * size + j]);
      }
    }
    uint8_t scale = galois_div(1, M[col * size + col]);
    for (unsigned j = 0; j < size; ++j) {
      M[col * size + j] = galois_mul(M[col * size + j], scale);
      inv[col * size + j] = galois_mul(inv[col * size + j], scale);
    }
    for (unsigned row = 0; row < size; ++row) {
      if (row == col) continue;
      uint8_t co = M[row * size + col];
      if (co == 0) continue;
      for (unsigned j = 0; j < size; ++j) {
        M[row * size + j] ^= galois_mul(co, M[col * size + j]);
        inv[row * size + j] ^= galois_mul(co, inv[col * size + j]);
      }
    }
  }
  for (unsigned i = 0; i < size * size; ++i) M[i] = inv[i];
  return true;
}

}  // namespace

void encode(unsigned k, unsigned m,
            const uint8_t* const* data_shards,
            uint8_t* const* parity_shards,
            size_t block_size) {
  ensure_galois();
  assert(k >= 1 && m >= 1 && k + m <= GF_SIZE);
  for (unsigned r = 0; r < m; ++r) {
    for (size_t col = 0; col < block_size; ++col) {
      uint8_t acc = 0;
      for (unsigned j = 0; j < k; ++j)
        acc ^= galois_mul(gen_coeff(r, j), data_shards[j][col]);
      parity_shards[r][col] = acc;
    }
  }
}

bool decode(unsigned n, unsigned k,
            const uint8_t* const* shard_ptrs,
            const unsigned* shard_indices,
            uint8_t* const* data_shards_out,
            size_t block_size) {
  ensure_galois();
  assert(n >= k && k >= 1 && n <= GF_SIZE);
  std::vector<uint8_t> M(k * k);
  for (unsigned a = 0; a < k; ++a) {
    unsigned row_idx = shard_indices[a];
    for (unsigned b = 0; b < k; ++b)
      M[a * k + b] = generator_coeff(n, k, row_idx, b);
  }
  if (!matrix_invert(M.data(), k)) return false;
  for (unsigned b = 0; b < k; ++b) {
    for (size_t col = 0; col < block_size; ++col) {
      uint8_t acc = 0;
      for (unsigned a = 0; a < k; ++a)
        acc ^= galois_mul(M[b * k + a], shard_ptrs[a][col]);
      data_shards_out[b][col] = acc;
    }
  }
  return true;
}

}  // namespace reed_solomon
