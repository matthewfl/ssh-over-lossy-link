# ssh-oll build: static binary, vendored Reed-Solomon.
# Requires C++17.
# On Linux: uses native epoll.
# On macOS: uses epoll-shim (kqueue-based). Requires: brew install epoll-shim

UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Darwin)
# macOS: use epoll-shim (kqueue-based). Install with: brew install epoll-shim
CXX           ?= clang++
EPOLL_SHIM_PREFIX ?= $(shell brew --prefix epoll-shim 2>/dev/null)
ifeq ($(EPOLL_SHIM_PREFIX),)
$(error epoll-shim not found. Install with: brew install epoll-shim)
endif
CXXFLAGS      = -std=c++17 -Wall -Wextra -O2 -I$(EPOLL_SHIM_PREFIX)/include/libepoll-shim
EPOLL_LDFLAGS = -L$(EPOLL_SHIM_PREFIX)/lib -lepoll-shim
else
# Linux: native epoll
CXX           ?= g++
CXXFLAGS      = -std=c++17 -Wall -Wextra -O2
EPOLL_LDFLAGS =
endif

REED_SOLOMON_OBJ = reed_solomon.o

.PHONY: all clean install

all: test_reed_solomon ssh-oll

reed_solomon.o: reed_solomon.cc reed_solomon.h
	$(CXX) $(CXXFLAGS) -c -o $@ reed_solomon.cc

test_reed_solomon: test_reed_solomon.cc $(REED_SOLOMON_OBJ)
	$(CXX) $(CXXFLAGS) -o $@ test_reed_solomon.cc $(REED_SOLOMON_OBJ) $(LDFLAGS_STATIC)

ssh-oll: main.o server.o client.o packet_io.o $(REED_SOLOMON_OBJ) ssholl.h
	$(CXX) $(CXXFLAGS) -o $@ main.o server.o client.o packet_io.o $(REED_SOLOMON_OBJ) $(EPOLL_LDFLAGS) $(LDFLAGS_STATIC)

main.o: main.cc ssholl.h
	$(CXX) $(CXXFLAGS) -c -o $@ main.cc

server.o: server.cc ssholl.h packet_io.h
	$(CXX) $(CXXFLAGS) -c -o $@ server.cc

client.o: client.cc ssholl.h packet_io.h
	$(CXX) $(CXXFLAGS) -c -o $@ client.cc

packet_io.o: packet_io.cc packet_io.h ssholl.h reed_solomon.h
	$(CXX) $(CXXFLAGS) -c -o $@ packet_io.cc

clean:
	rm -f $(REED_SOLOMON_OBJ) test_reed_solomon ssh-oll main.o server.o client.o packet_io.o

install: all
	install -d $(DESTDIR)/usr/local/bin
	install -m 755 ssh-oll $(DESTDIR)/usr/local/bin
	@echo "Installed ssh-oll to $(DESTDIR)/usr/local/bin"
