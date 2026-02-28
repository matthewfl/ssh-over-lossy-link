// Minimal test for Reed-Solomon encode/decode. Links with static library to verify build.
#include "reed_solomon.h"
#include <cstdio>
#include <cstring>
#include <vector>

int main() {
  const unsigned k = 4, m = 2, n = k + m;
  const size_t block_size = 64;
  std::vector<std::vector<uint8_t>> data(k, std::vector<uint8_t>(block_size));
  std::vector<std::vector<uint8_t>> parity(m, std::vector<uint8_t>(block_size));
  for (unsigned i = 0; i < k; ++i)
    for (size_t j = 0; j < block_size; ++j)
      data[i][j] = static_cast<uint8_t>(i * 31 + j);

  std::vector<const uint8_t*> data_ptrs(k);
  std::vector<uint8_t*> parity_ptrs(m);
  for (unsigned i = 0; i < k; ++i) data_ptrs[i] = data[i].data();
  for (unsigned i = 0; i < m; ++i) parity_ptrs[i] = parity[i].data();

  reed_solomon::encode(k, m, data_ptrs.data(), parity_ptrs.data(), block_size);

  // Simulate loss of data shards 1 and 2; keep data 0, 3 and both parity shards.
  std::vector<const uint8_t*> received_ptrs(k);
  std::vector<unsigned> indices = { 0, 3, 4, 5 };  // data 0, data 3, parity 0, parity 1
  received_ptrs[0] = data[0].data();
  received_ptrs[1] = data[3].data();
  received_ptrs[2] = parity[0].data();
  received_ptrs[3] = parity[1].data();

  std::vector<std::vector<uint8_t>> recovered(k, std::vector<uint8_t>(block_size));
  std::vector<uint8_t*> out_ptrs(k);
  for (unsigned i = 0; i < k; ++i) out_ptrs[i] = recovered[i].data();

  if (!reed_solomon::decode(n, k, received_ptrs.data(), indices.data(), out_ptrs.data(), block_size)) {
    std::fprintf(stderr, "decode failed\n");
    return 1;
  }
  for (unsigned i = 0; i < k; ++i) {
    if (std::memcmp(recovered[i].data(), data[i].data(), block_size) != 0) {
      std::fprintf(stderr, "mismatch at shard %u\n", i);
      return 1;
    }
  }
  std::printf("reed_solomon encode/decode OK\n");
  return 0;
}
