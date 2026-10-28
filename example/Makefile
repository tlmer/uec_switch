CXX ?= g++
CXXFLAGS ?= -std=c++14 -O2 -Wall -Wextra -I../include

all: uec_example
uec_example: uec_example.cpp
	$(CXX) $(CXXFLAGS) $< -o $@

test: all
	./uec_example

clean:
	rm -f uec_example

.PHONY: all test clean
