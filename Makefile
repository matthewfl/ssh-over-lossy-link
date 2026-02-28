# ssh-oll build: static binary, vendored Reed-Solomon.
# Requires C++17.

CXX     ?= g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2
LDFLAGS_STATIC = -static

REED_SOLOMON_OBJ = reed_solomon.o
LIBREED_SOLOMON = libreed_solomon.a

.PHONY: all clean install

all: $(LIBREED_SOLOMON) test_reed_solomon ssh-oll

$(LIBREED_SOLOMON): $(REED_SOLOMON_OBJ)
	$(AR) rcs $@ $^

reed_solomon.o: reed_solomon.cc reed_solomon.h
	$(CXX) $(CXXFLAGS) -c -o $@ reed_solomon.cc

test_reed_solomon: test_reed_solomon.cc $(LIBREED_SOLOMON)
	$(CXX) $(CXXFLAGS) -o $@ test_reed_solomon.cc $(LIBREED_SOLOMON) $(LDFLAGS_STATIC)

ssh-oll: main.o server.o ssholl.h
	$(CXX) $(CXXFLAGS) -o $@ main.o server.o $(LDFLAGS_STATIC)

main.o: main.cc ssholl.h
	$(CXX) $(CXXFLAGS) -c -o $@ main.cc

server.o: server.cc ssholl.h
	$(CXX) $(CXXFLAGS) -c -o $@ server.cc

clean:
	rm -f $(REED_SOLOMON_OBJ) $(LIBREED_SOLOMON) test_reed_solomon ssh-oll main.o server.o

install: all
	install -d $(DESTDIR)/usr/local/bin
	install -m 755 ssh-oll $(DESTDIR)/usr/local/bin
	@echo "Installed ssh-oll to $(DESTDIR)/usr/local/bin"
