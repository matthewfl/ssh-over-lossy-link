# ssh-oll build: static binary, vendored Reed-Solomon.
# Requires C++17.

CXX     ?= g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2
LDFLAGS_STATIC = -static

REED_SOLOMON_OBJ = reed_solomon.o
LIBREED_SOLOMON = libreed_solomon.a

.PHONY: all clean install

all: $(LIBREED_SOLOMON) test_reed_solomon

$(LIBREED_SOLOMON): $(REED_SOLOMON_OBJ)
	$(AR) rcs $@ $^

reed_solomon.o: reed_solomon.cc reed_solomon.h
	$(CXX) $(CXXFLAGS) -c -o $@ reed_solomon.cc

test_reed_solomon: test_reed_solomon.cc $(LIBREED_SOLOMON)
	$(CXX) $(CXXFLAGS) -o $@ test_reed_solomon.cc $(LIBREED_SOLOMON) $(LDFLAGS_STATIC)

clean:
	rm -f $(REED_SOLOMON_OBJ) $(LIBREED_SOLOMON) test_reed_solomon

install: all
	# Future: install ssh-oll binary and optionally libreed_solomon.a / headers
	@echo "Install target TBD when ssh-oll binary is added."
