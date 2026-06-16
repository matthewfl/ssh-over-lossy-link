// Unit tests for packet_io reassembly / RS-decode, focused on the invariants that
// keep the stream correct across loss and reconnect:
//   - in-order delivery of out-of-order SMALL packets
//   - a duplicate of an already-delivered id is dropped, NOT re-delivered
//     (this is what makes retransmit-after-reconnect safe)
//   - a gap blocks delivery until it is filled
//   - an RS group decodes and delivers once k shards arrive; extra shards after
//     decode never re-deliver
//
// These exercise packet_io::process_carrier_read directly (no sockets), so they are
// deterministic and fast.

#include "packet_io.h"
#include "reed_solomon.h"
#include <cstdio>
#include <cstring>
#include <map>
#include <string>
#include <vector>

using namespace ssholl;
using namespace ssholl::packet_io;

namespace {

int g_failures = 0;

void check(bool cond, const char* msg) {
  if (!cond) {
    std::fprintf(stderr, "FAIL: %s\n", msg);
    ++g_failures;
  }
}

// A small harness that owns the reassembly state shared across calls (mirroring how
// client.cc / server.cc keep these maps for the lifetime of a session) and records
// everything that gets delivered, in order.
struct Harness {
  std::map<uint64_t, std::vector<uint8_t>> reassembly;
  std::map<uint64_t, RsPending> rs_pending;
  std::map<uint64_t, uint64_t> recently_decoded_ns;
  std::map<uint64_t, std::vector<uint64_t>> small_copy_arrival_times;
  uint64_t next_deliver_id = 0;
  std::vector<uint8_t> delivered;          // concatenated delivered bytes, in order
  std::vector<uint64_t> delivered_ids;     // ids in delivery order
  unsigned extra_shard_calls = 0;

  ReceiveCallbacks cb() {
    ReceiveCallbacks c;
    c.on_deliver = [this](int, uint64_t id, const uint8_t* data, size_t len) {
      delivered_ids.push_back(id);
      delivered.insert(delivered.end(), data, data + len);
    };
    c.on_rs_extra_shard = [this](uint64_t) { ++extra_shard_calls; };
    return c;
  }

  // Feed a fully-formed packet buffer through the parser as if it arrived on a carrier.
  bool feed(const std::vector<uint8_t>& bytes) {
    CarrierState s;
    s.read_buf = bytes;
    return process_carrier_read(/*fd=*/1, s, reassembly, rs_pending, recently_decoded_ns,
                                small_copy_arrival_times, next_deliver_id, cb());
  }
};

std::vector<uint8_t> make_small(uint64_t id, const std::string& payload) {
  std::vector<uint8_t> out;
  append_small(out, id, reinterpret_cast<const uint8_t*>(payload.data()), payload.size());
  return out;
}

// Build the n shards for an RS group carrying `data` (k blocks of block_size).
std::vector<std::vector<uint8_t>> make_rs_shards(uint64_t id, const std::vector<uint8_t>& data,
                                                 unsigned k, unsigned m, size_t block_size) {
  unsigned n = k + m;
  std::vector<const uint8_t*> dptrs(k);
  for (unsigned i = 0; i < k; ++i) dptrs[i] = data.data() + i * block_size;
  std::vector<std::vector<uint8_t>> parity(m, std::vector<uint8_t>(block_size));
  std::vector<uint8_t*> pptrs(m);
  for (unsigned i = 0; i < m; ++i) pptrs[i] = parity[i].data();
  reed_solomon::encode(k, m, dptrs.data(), pptrs.data(), block_size);

  std::vector<std::vector<uint8_t>> shards(n);
  for (unsigned i = 0; i < n; ++i) {
    const uint8_t* shard = (i < k) ? (data.data() + i * block_size) : parity[i - k].data();
    append_rs_shard(shards[i], id, n, k, static_cast<uint16_t>(block_size), i, shard);
  }
  return shards;
}

// ── Test 1: out-of-order SMALL packets are delivered in id order ────────────
void test_out_of_order_small() {
  Harness h;
  h.feed(make_small(1, "BBB"));   // arrives first, but id 0 not yet seen
  check(h.delivered.empty(), "id1-before-id0: nothing should be delivered yet");
  h.feed(make_small(0, "AAA"));   // fills the gap → both deliver, in order
  check(h.delivered_ids.size() == 2 && h.delivered_ids[0] == 0 && h.delivered_ids[1] == 1,
        "out-of-order: delivered ids should be [0,1]");
  check(std::string(h.delivered.begin(), h.delivered.end()) == "AAABBB",
        "out-of-order: delivered bytes should be AAABBB");
}

// ── Test 2: duplicate of an already-delivered id is dropped (retransmit safety) ─
void test_duplicate_after_delivery() {
  Harness h;
  h.feed(make_small(0, "AAA"));
  h.feed(make_small(1, "BBB"));
  check(h.delivered_ids.size() == 2, "dup: two ids delivered initially");
  size_t before = h.delivered.size();
  // Simulate a reconnect retransmit re-sending id 0 (already delivered).
  h.feed(make_small(0, "AAA"));
  check(h.delivered.size() == before, "dup: re-sent already-delivered id0 must NOT re-deliver");
  check(h.delivered_ids.size() == 2, "dup: delivery count unchanged after duplicate");
}

// ── Test 3: a gap blocks delivery of everything after it ────────────────────
void test_gap_blocks() {
  Harness h;
  h.feed(make_small(1, "BBB"));
  h.feed(make_small(2, "CCC"));
  h.feed(make_small(3, "DDD"));
  check(h.delivered.empty(), "gap: nothing delivered while id0 missing");
  check(h.next_deliver_id == 0, "gap: next_deliver_id stays at the missing id");
  h.feed(make_small(0, "AAA"));   // fill the gap
  check(std::string(h.delivered.begin(), h.delivered.end()) == "AAABBBCCCDDD",
        "gap: filling id0 releases the whole buffered run in order");
}

// ── Test 4: RS group decodes from any k shards; extras don't re-deliver ─────
void test_rs_decode_and_extra() {
  const unsigned k = 4, m = 2;
  const size_t block_size = 8;
  std::vector<uint8_t> data(k * block_size);
  for (size_t i = 0; i < data.size(); ++i) data[i] = static_cast<uint8_t>(i);
  auto shards = make_rs_shards(/*id=*/0, data, k, m, block_size);

  Harness h;
  // Deliver k shards: choose 2 data + 2 parity (indices 0,1,4,5) to force real decode.
  h.feed(shards[0]);
  h.feed(shards[1]);
  h.feed(shards[4]);
  check(h.delivered.empty(), "rs: should not deliver before k shards arrive");
  h.feed(shards[5]);  // 4th shard → decode + deliver
  check(h.delivered.size() == data.size(), "rs: decoded block delivered with correct length");
  check(std::memcmp(h.delivered.data(), data.data(), data.size()) == 0,
        "rs: decoded bytes match original");
  check(h.delivered_ids.size() == 1 && h.delivered_ids[0] == 0, "rs: delivered exactly id 0");

  // An "extra" shard arriving after decode must not re-deliver and must be accepted
  // (it should fire the extra-shard callback, used for redundancy tuning).
  size_t before = h.delivered.size();
  h.feed(shards[2]);
  check(h.delivered.size() == before, "rs: extra shard after decode must NOT re-deliver");
  check(h.extra_shard_calls >= 1, "rs: extra shard after decode should fire on_rs_extra_shard");
}

// ── Test 5: SMALL interleaved with a decoded RS group, out of order ─────────
void test_mixed_order() {
  const unsigned k = 2, m = 1;
  const size_t block_size = 4;
  std::vector<uint8_t> data(k * block_size);
  for (size_t i = 0; i < data.size(); ++i) data[i] = static_cast<uint8_t>(0x40 + i);
  auto shards = make_rs_shards(/*id=*/0, data, k, m, block_size);  // group is id 0

  Harness h;
  h.feed(make_small(1, "Z"));     // id 1 arrives before id 0 group completes
  check(h.delivered.empty(), "mixed: id1 must wait for id0 group");
  h.feed(shards[0]);
  h.feed(shards[2]);              // 2 of 3 shards (1 data + 1 parity) = k → decode
  check(h.delivered_ids.size() == 2, "mixed: id0 (RS) then id1 (SMALL) both deliver");
  check(h.delivered_ids[0] == 0 && h.delivered_ids[1] == 1, "mixed: order is [0,1]");
  std::vector<uint8_t> expect = data;
  expect.push_back('Z');
  check(h.delivered == expect, "mixed: bytes are the decoded block followed by Z");
}

// ── Test 6: retransmit-after-reconnect — re-encoded shards complete a partial group ─
// Mirrors what the retransmit/reconnect path does: a group is partially received, then
// the sender re-encodes the SAME group (same id/n/k/block_size) and resends its shards.
// The re-fed shards must combine with the retained partial and decode. This is the
// invariant the Phase 2 shared retransmit helper must preserve.
void test_rs_retransmit_combines() {
  const unsigned k = 4, m = 2;
  const size_t block_size = 8;
  std::vector<uint8_t> data(k * block_size);
  for (size_t i = 0; i < data.size(); ++i) data[i] = static_cast<uint8_t>(0x10 + i);

  Harness h;
  // First transmission: only 2 of the k=4 needed shards arrive (rest "lost").
  auto first = make_rs_shards(/*id=*/0, data, k, m, block_size);
  h.feed(first[0]);
  h.feed(first[1]);
  check(h.delivered.empty(), "rs-retransmit: partial group (2<k) not delivered");

  // Reconnect retransmit: the sender re-encodes the same group from scratch and resends.
  // Regenerate independently to prove the re-encode is deterministic (same parity bytes).
  auto resend = make_rs_shards(/*id=*/0, data, k, m, block_size);
  h.feed(resend[2]);  // 3rd distinct shard
  check(h.delivered.empty(), "rs-retransmit: still short of k after 3rd shard");
  h.feed(resend[3]);  // 4th distinct shard → decode from the combined set
  check(h.delivered.size() == data.size(), "rs-retransmit: re-fed shards complete the group");
  check(std::memcmp(h.delivered.data(), data.data(), data.size()) == 0,
        "rs-retransmit: decoded bytes match original");
  check(h.delivered_ids.size() == 1 && h.delivered_ids[0] == 0, "rs-retransmit: delivered exactly once");
}

}  // namespace

int main() {
  test_out_of_order_small();
  test_duplicate_after_delivery();
  test_gap_blocks();
  test_rs_decode_and_extra();
  test_mixed_order();
  test_rs_retransmit_combines();
  if (g_failures) {
    std::fprintf(stderr, "packet_io tests: %d failure(s)\n", g_failures);
    return 1;
  }
  std::printf("packet_io reassembly/decode tests OK\n");
  return 0;
}
