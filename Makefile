# ssh-oll build: static binary, vendored Reed-Solomon.
# Requires C++17.

CXX     ?= g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2

REED_SOLOMON_OBJ = reed_solomon.o

.PHONY: all clean install

all: test_reed_solomon ssh-oll

reed_solomon.o: reed_solomon.cc reed_solomon.h
	$(CXX) $(CXXFLAGS) -c -o $@ reed_solomon.cc

test_reed_solomon: test_reed_solomon.cc $(REED_SOLOMON_OBJ)
	$(CXX) $(CXXFLAGS) -o $@ test_reed_solomon.cc $(REED_SOLOMON_OBJ) $(LDFLAGS_STATIC)

ssh-oll: main.o server.o client.o $(REED_SOLOMON_OBJ) ssholl.h
	$(CXX) $(CXXFLAGS) -o $@ main.o server.o client.o $(REED_SOLOMON_OBJ) $(LDFLAGS_STATIC)

main.o: main.cc ssholl.h
	$(CXX) $(CXXFLAGS) -c -o $@ main.cc

server.o: server.cc ssholl.h
	$(CXX) $(CXXFLAGS) -c -o $@ server.cc

client.o: client.cc ssholl.h
	$(CXX) $(CXXFLAGS) -c -o $@ client.cc

clean:
	rm -f $(REED_SOLOMON_OBJ) test_reed_solomon ssh-oll main.o server.o client.o

install: all
	install -d $(DESTDIR)/usr/local/bin
	install -m 755 ssh-oll $(DESTDIR)/usr/local/bin
	@echo "Installed ssh-oll to $(DESTDIR)/usr/local/bin"
