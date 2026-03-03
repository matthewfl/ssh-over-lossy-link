#include "packet_io.h"
#include "reed_solomon.h"
#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <sys/epoll.h>
#include <unistd.h>

namespace ssholl {

namespace packet_io {

bool process_carrier_read(
  int fd,
  CarrierState& s,
  std::map<uint64_t, std::vector<uint8_t>>& reassembly,
  std::map<uint64_t, RsPending>& rs_pending,
  std::map<uint64_t, uint64_t>& recently_decoded_ns,
  std::map<uint64_t, std::vector<uint64_t>>& small_copy_arrival_times,
  uint64_t& next_deliver_id,
  const ReceiveCallbacks& callbacks) {
  auto now_ns = []() -> uint64_t {
    return static_cast<uint64_t>(
        std::chrono::steady_clock::now().time_since_epoch().count());
  };
  while (s.read_buf.size() >= sizeof(PacketHeader)) {
    // Any recognised packet counts as activity on this carrier.
    s.last_recv_ns = now_ns();
    const auto* h = reinterpret_cast<const PacketHeader*>(s.read_buf.data());
    if (h->packet_kind == PacketKind::PING) {
      if (callbacks.on_ping) callbacks.on_ping(fd, h->id);
      s.read_buf.erase(s.read_buf.begin(), s.read_buf.begin() + sizeof(PacketHeader));
      continue;
    }
    if (h->packet_kind == PacketKind::PONG) {
      uint64_t id = h->id;
      s.read_buf.erase(s.read_buf.begin(), s.read_buf.begin() + sizeof(PacketHeader));
      if (callbacks.on_pong) callbacks.on_pong(fd, id);
      continue;
    }
    if (h->packet_kind == PacketKind::ACK) {
      uint64_t acked_id = h->id;
      s.read_buf.erase(s.read_buf.begin(), s.read_buf.begin() + sizeof(PacketHeader));
      if (callbacks.on_ack) callbacks.on_ack(fd, acked_id);
      continue;
    }
    if (h->packet_kind == PacketKind::SMALL) {
      if (s.read_buf.size() < sizeof(PacketSmall)) break;
      const auto* p = reinterpret_cast<const PacketSmall*>(s.read_buf.data());
      uint16_t size = p->size;
      if (size > MAX_PACKET_PAYLOAD) {
        s.read_buf.clear();
        return false;
      }
      size_t total = sizeof(PacketHeader) + sizeof(uint16_t) + size;
      if (s.read_buf.size() < total) break;
      uint64_t id = h->id;
      const uint64_t t = now_ns();
      if (id >= next_deliver_id && !reassembly.count(id)) {
        reassembly[id].assign(p->data, p->data + size);
        s.last_recv_ns = t;
        small_copy_arrival_times[id] = {t};
      } else if (small_copy_arrival_times.count(id)) {
        auto& times = small_copy_arrival_times[id];
        times.push_back(t);
        if (times.size() >= 2 && callbacks.on_small_extra_copy) {
          std::vector<uint64_t> sorted = times;
          std::sort(sorted.begin(), sorted.end());
          uint64_t gap = sorted[sorted.size() / 2] - sorted[0];  // first → median
          callbacks.on_small_extra_copy(gap);
        }
        small_copy_arrival_times.erase(id);
      }
      s.read_buf.erase(s.read_buf.begin(), s.read_buf.begin() + total);
      while (reassembly.count(next_deliver_id)) {
        std::vector<uint8_t>& vec = reassembly[next_deliver_id];
        if (callbacks.on_deliver)
          callbacks.on_deliver(fd, next_deliver_id, vec.data(), vec.size());
        reassembly.erase(next_deliver_id);
        next_deliver_id++;
      }
      for (auto it = small_copy_arrival_times.begin(); it != small_copy_arrival_times.end(); ) {
        if (it->first + 100 < next_deliver_id) it = small_copy_arrival_times.erase(it);
        else ++it;
      }
      continue;
    }
    if (h->packet_kind == PacketKind::SET_CONFIG) {
      if (s.read_buf.size() < sizeof(PacketConfig)) break;
      PacketConfig pc;
      std::memcpy(&pc, s.read_buf.data(), sizeof(pc));
      s.read_buf.erase(s.read_buf.begin(), s.read_buf.begin() + sizeof(PacketConfig));
      if (callbacks.on_set_config) callbacks.on_set_config(pc);
      continue;
    }
    if (h->packet_kind == PacketKind::START_CONNECTION) {
      s.read_buf.erase(s.read_buf.begin(), s.read_buf.begin() + sizeof(PacketHeader));
      continue;
    }
    if (h->packet_kind == PacketKind::READY) {
      s.read_buf.erase(s.read_buf.begin(), s.read_buf.begin() + sizeof(PacketHeader));
      continue;  // header-only; last_recv_ns already updated; confirms server is ready
    }
    if (h->packet_kind == PacketKind::SUGGEST_CLOSE) {
      s.read_buf.erase(s.read_buf.begin(), s.read_buf.begin() + sizeof(PacketHeader));
      if (callbacks.on_suggest_close) callbacks.on_suggest_close(fd);
      continue;
    }
    if (h->packet_kind == PacketKind::SERVER_METRICS) {
      if (s.read_buf.size() < sizeof(PacketServerMetrics)) break;
      PacketServerMetrics pm;
      std::memcpy(&pm, s.read_buf.data(), sizeof(pm));
      s.read_buf.erase(s.read_buf.begin(), s.read_buf.begin() + sizeof(PacketServerMetrics));
      if (callbacks.on_server_metrics)
        callbacks.on_server_metrics(pm.max_rtt_ns, pm.avg_shard_spread_ns,
                                    pm.avg_extra_shard_gap_ns, pm.rs_pending_count);
      continue;
    }
    if (h->packet_kind == PacketKind::SERVER_CONFIG) {
      if (s.read_buf.size() < sizeof(PacketServerConfig)) break;
      PacketServerConfig psc;
      std::memcpy(&psc, s.read_buf.data(), sizeof(psc));
      s.read_buf.erase(s.read_buf.begin(), s.read_buf.begin() + sizeof(PacketServerConfig));
      if (callbacks.on_server_config) callbacks.on_server_config(psc);
      continue;
    }
    if (h->packet_kind == PacketKind::REED_SOLOMON) {
      const size_t rs_fixed = sizeof(PacketHeader) + sizeof(uint16_t) + 3;
      if (s.read_buf.size() < rs_fixed) break;
      uint16_t block_sz = *reinterpret_cast<const uint16_t*>(s.read_buf.data() + sizeof(PacketHeader));
      const auto* prs = reinterpret_cast<const PacketReedSolomon*>(s.read_buf.data());
      size_t total_rs = rs_fixed + block_sz;
      if (block_sz == 0 || block_sz > MAX_PACKET_PAYLOAD || s.read_buf.size() < total_rs) break;
      uint64_t id = h->id;
      unsigned n = prs->n, k = prs->k;
      if (id < next_deliver_id) {
        // Group already decoded; this is an "extra" shard arriving late.
        // If it's the first extra shard for this group, fire on_rs_extra_shard so
        // the caller can measure the gap between the k-th and (k+1)-th shard.
        if (callbacks.on_rs_extra_shard) {
          auto it = recently_decoded_ns.find(id);
          if (it != recently_decoded_ns.end()) {
            callbacks.on_rs_extra_shard(now_ns() - it->second);
            recently_decoded_ns.erase(it);  // only report first extra shard per group
          }
        }
        s.read_buf.erase(s.read_buf.begin(), s.read_buf.begin() + total_rs);
        continue;
      }
      if (n == 0 || k == 0 || k >= n || n > 256) {
        s.read_buf.erase(s.read_buf.begin(), s.read_buf.begin() + total_rs);
        continue;
      }
      RsPending& rp = rs_pending[id];
      if (rp.k == 0) {
        rp.n = n;
        rp.k = k;
        rp.block_size = block_sz;
        rp.first_recv_ns = now_ns();
      }
      if (rp.n != n || rp.k != k || rp.block_size != block_sz) {
        s.read_buf.erase(s.read_buf.begin(), s.read_buf.begin() + total_rs);
        continue;
      }
      unsigned idx = prs->shard_index;
      if (idx >= n) {
        s.read_buf.erase(s.read_buf.begin(), s.read_buf.begin() + total_rs);
        continue;
      }
      if (!rp.shards.count(idx)) {
        uint64_t t = now_ns();
        rp.shards[idx].assign(prs->data, prs->data + block_sz);
        rp.shard_recv_ns[idx] = t;
        s.last_recv_ns = t;
      }
      s.read_buf.erase(s.read_buf.begin(), s.read_buf.begin() + total_rs);
      if (rp.shards.size() >= static_cast<size_t>(k)) {
        std::vector<const uint8_t*> recv_ptrs(k);
        std::vector<unsigned> recv_indices(k);
        unsigned fi = 0;
        for (auto& [shard_idx, vec] : rp.shards) {
          if (fi >= k) break;
          recv_ptrs[fi] = vec.data();
          recv_indices[fi] = shard_idx;
          fi++;
        }
        if (fi < k) continue;
        std::vector<std::vector<uint8_t>> out_shards(k, std::vector<uint8_t>(rp.block_size));
        std::vector<uint8_t*> out_ptrs(k);
        for (unsigned i = 0; i < k; ++i) out_ptrs[i] = out_shards[i].data();
        if (reed_solomon::decode(rp.n, rp.k, recv_ptrs.data(), recv_indices.data(), out_ptrs.data(), rp.block_size)) {
          if (!reassembly.count(id)) {
            reassembly[id].clear();
            for (unsigned i = 0; i < k; ++i)
              reassembly[id].insert(reassembly[id].end(), out_shards[i].begin(), out_shards[i].end());
          }
        }
        if (callbacks.on_rs_decode || callbacks.on_rs_extra_shard) {
          // Sort per-shard arrival times to compute spread and the final inter-shard gap.
          std::vector<uint64_t> times;
          times.reserve(rp.shard_recv_ns.size());
          for (auto& [si, t] : rp.shard_recv_ns) times.push_back(t);
          std::sort(times.begin(), times.end());
          uint64_t shard_spread_ns = times[k - 1] - times[0];
          uint64_t gap_final_ns = (k >= 2) ? (times[k - 1] - times[k - 2]) : 0;
          uint64_t decode_time_ns = times[k - 1];
          if (callbacks.on_rs_decode)
            callbacks.on_rs_decode(static_cast<unsigned>(rp.shards.size()), rp.n,
                                   shard_spread_ns, gap_final_ns);
          // Record decode time so we can measure the k→(k+1) gap when the next shard arrives.
          if (callbacks.on_rs_extra_shard) {
            recently_decoded_ns[id] = decode_time_ns;
            // Prune to avoid unbounded growth: keep only the last 64 decoded groups.
            while (recently_decoded_ns.size() > 64)
              recently_decoded_ns.erase(recently_decoded_ns.begin());
          }
        }
        rs_pending.erase(id);
        while (reassembly.count(next_deliver_id)) {
          std::vector<uint8_t>& vec = reassembly[next_deliver_id];
          if (callbacks.on_deliver)
            callbacks.on_deliver(fd, next_deliver_id, vec.data(), vec.size());
          reassembly.erase(next_deliver_id);
          next_deliver_id++;
        }
      }
      continue;
    }
    s.read_buf.erase(s.read_buf.begin(), s.read_buf.begin() + sizeof(PacketHeader));
  }
  return true;
}

void append_small(std::vector<uint8_t>& out, uint64_t id, const uint8_t* data, size_t len) {
  PacketHeader h{};
  h.id = id;
  h.packet_kind = PacketKind::SMALL;
  uint16_t size = static_cast<uint16_t>(len);
  out.insert(out.end(), reinterpret_cast<uint8_t*>(&h), reinterpret_cast<uint8_t*>(&h) + sizeof h);
  out.insert(out.end(), reinterpret_cast<uint8_t*>(&size), reinterpret_cast<uint8_t*>(&size) + sizeof size);
  out.insert(out.end(), data, data + len);
}

void append_rs_shard(std::vector<uint8_t>& out, uint64_t id, unsigned n, unsigned k,
                     uint16_t block_size, unsigned shard_index, const uint8_t* shard_data) {
  PacketHeader h{};
  h.id = id;
  h.packet_kind = PacketKind::REED_SOLOMON;
  uint16_t size = block_size;
  out.insert(out.end(), reinterpret_cast<uint8_t*>(&h), reinterpret_cast<uint8_t*>(&h) + sizeof h);
  out.insert(out.end(), reinterpret_cast<uint8_t*>(&size), reinterpret_cast<uint8_t*>(&size) + sizeof size);
  out.push_back(static_cast<uint8_t>(n));
  out.push_back(static_cast<uint8_t>(k));
  out.push_back(static_cast<uint8_t>(shard_index));
  out.insert(out.end(), shard_data, shard_data + block_size);
}

void append_config(std::vector<uint8_t>& out, uint16_t packet_size, uint16_t small_packet_redundancy,
                   float max_delay_ms, float reed_solomon_redundancy, uint8_t auto_adapt) {
  PacketConfig pc{};
  pc.header.id = 0;
  pc.header.packet_kind = PacketKind::SET_CONFIG;
  pc.packet_size = packet_size;
  pc.small_packet_redundancy = small_packet_redundancy;
  pc.max_delay_ms = max_delay_ms;
  pc.reed_solomon_redundancy = reed_solomon_redundancy;
  pc.auto_adapt = auto_adapt;
  const uint8_t* p = reinterpret_cast<const uint8_t*>(&pc);
  out.insert(out.end(), p, p + sizeof pc);
}

void append_server_config(std::vector<uint8_t>& out, uint16_t packet_size, uint16_t small_packet_redundancy,
                          float max_delay_ms, float reed_solomon_redundancy) {
  PacketServerConfig psc{};
  psc.header.id = 0;
  psc.header.packet_kind = PacketKind::SERVER_CONFIG;
  psc.packet_size = packet_size;
  psc.small_packet_redundancy = small_packet_redundancy;
  psc.max_delay_ms = max_delay_ms;
  psc.reed_solomon_redundancy = reed_solomon_redundancy;
  const uint8_t* p = reinterpret_cast<const uint8_t*>(&psc);
  out.insert(out.end(), p, p + sizeof psc);
}

void append_ack(std::vector<uint8_t>& out, uint64_t acked_id) {
  PacketHeader h{};
  h.id = acked_id;
  h.packet_kind = PacketKind::ACK;
  out.insert(out.end(), reinterpret_cast<uint8_t*>(&h), reinterpret_cast<uint8_t*>(&h) + sizeof h);
}

void append_pong(std::vector<uint8_t>& out, uint64_t id) {
  PacketHeader h{};
  h.id = id;
  h.packet_kind = PacketKind::PONG;
  out.insert(out.end(), reinterpret_cast<uint8_t*>(&h), reinterpret_cast<uint8_t*>(&h) + sizeof h);
}

void append_ping(std::vector<uint8_t>& out, uint64_t id) {
  PacketHeader h{};
  h.id = id;
  h.packet_kind = PacketKind::PING;
  out.insert(out.end(), reinterpret_cast<uint8_t*>(&h), reinterpret_cast<uint8_t*>(&h) + sizeof h);
}

void append_ready(std::vector<uint8_t>& out) {
  PacketHeader h{};
  h.id = 0;
  h.packet_kind = PacketKind::READY;
  out.insert(out.end(), reinterpret_cast<uint8_t*>(&h), reinterpret_cast<uint8_t*>(&h) + sizeof h);
}

void append_suggest_close(std::vector<uint8_t>& out) {
  PacketHeader h{};
  h.id = 0;
  h.packet_kind = PacketKind::SUGGEST_CLOSE;
  out.insert(out.end(), reinterpret_cast<uint8_t*>(&h), reinterpret_cast<uint8_t*>(&h) + sizeof h);
}

void append_server_metrics(std::vector<uint8_t>& out, uint64_t max_rtt_ns,
                           uint64_t avg_shard_spread_ns, uint64_t avg_extra_shard_gap_ns,
                           uint32_t rs_pending_count) {
  PacketServerMetrics pm{};
  pm.header.id = 0;
  pm.header.packet_kind = PacketKind::SERVER_METRICS;
  pm.max_rtt_ns = max_rtt_ns;
  pm.avg_shard_spread_ns = avg_shard_spread_ns;
  pm.avg_extra_shard_gap_ns = avg_extra_shard_gap_ns;
  pm.rs_pending_count = rs_pending_count;
  const uint8_t* p = reinterpret_cast<const uint8_t*>(&pm);
  out.insert(out.end(), p, p + sizeof pm);
}

void flush_carrier_writes(
  std::map<int, CarrierState>& carriers,
  int epfd,
  struct epoll_event& ev,
  std::function<bool(int fd, const CarrierState&)> skip_write,
  std::function<void(int fd, const char* reason)> on_removed) {
  for (auto it = carriers.begin(); it != carriers.end(); ) {
    int fd = it->first;
    CarrierState& s = it->second;
    if (skip_write && skip_write(fd, s)) {
      ++it;
      continue;
    }
    while (s.write_pos < s.write_buf.size()) {
      ssize_t n = write(fd, s.write_buf.data() + s.write_pos, s.write_buf.size() - s.write_pos);
      if (n <= 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          ev.events = EPOLLIN | EPOLLOUT;
          ev.data.fd = fd;
          epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev);
          break;
        }
        if (on_removed) on_removed(fd, "write_error");
        close(fd);
        epoll_ctl(epfd, EPOLL_CTL_DEL, fd, nullptr);
        it = carriers.erase(it);
        goto next;
      }
      s.write_pos += n;
      s.last_send_ns = static_cast<uint64_t>(
          std::chrono::steady_clock::now().time_since_epoch().count());
    }
    if (s.write_pos >= s.write_buf.size()) {
      s.write_buf.clear();
      s.write_pos = 0;
      ev.events = EPOLLIN;
      ev.data.fd = fd;
      epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev);
    }
    ++it;
    next:;
  }
}

}  // namespace packet_io
}  // namespace ssholl
