#ifndef SSH_OLL_REED_SOLOMON_H
#define SSH_OLL_REED_SOLOMON_H

#include <cstddef>
#include <cstdint>

namespace reed_solomon {

// Reed-Solomon erasure coding over GF(2^8). Systematic encoding: first k
// shards are the data; the next m = n - k shards are parity. Any k of n
// shards suffice to reconstruct the k data shards.
//
// All shards must be the same length (block_size bytes). n and k must satisfy
// 1 <= k < n <= 256.

// Encode: compute parity from data.
//   k, m          - data shard count and parity shard count (n = k + m).
//   data_shards   - k pointers to data shard buffers (each block_size bytes).
//   parity_shards - m pointers to parity shard buffers (each block_size bytes); filled on return.
//   block_size    - length of each shard in bytes.
void encode(unsigned k, unsigned m,
            const uint8_t* const* data_shards,
            uint8_t* const* parity_shards,
            size_t block_size);

// Decode: recover data from k received shards (any k of n).
//   n, k            - total shards and data shard count (m = n - k).
//   shard_ptrs      - k pointers to the received shard buffers (each block_size bytes).
//   shard_indices   - k indices in [0, n) identifying which shard each pointer is (data 0..k-1, parity k..n-1).
//   data_shards_out - k pointers to buffers for the recovered data shards (each block_size bytes); filled on return.
//   block_size      - length of each shard in bytes.
// Returns true on success; false if the chosen indices are not solvable (e.g. singular matrix).
bool decode(unsigned n, unsigned k,
            const uint8_t* const* shard_ptrs,
            const unsigned* shard_indices,
            uint8_t* const* data_shards_out,
            size_t block_size);

}  // namespace reed_solomon

#endif /* SSH_OLL_REED_SOLOMON_H */
