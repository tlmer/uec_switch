CXX ?= g++
CXXFLAGS ?= -std=c++14 -O2 -Wall -Wextra -I../include
SYSTEMC_HOME ?= /opt/tools/systemc2.34
SCFLAGS = -I$(SYSTEMC_HOME)/include
SCLIBS  = -L$(SYSTEMC_HOME)/lib-linux64 -lsystemc -lpthread

all: uec_console
uec_console: uec_console_main.cpp
	$(CXX) $(CXXFLAGS) $(SCFLAGS) $< -L../lib -luec_model $(SCLIBS) -o $@

test: all
	printf 'info\nstats 0\nqueue 0 0\nrun 1000\nquit\n' | \
	  LD_LIBRARY_PATH=$(SYSTEMC_HOME)/lib-linux64 ./uec_console ../config/default.yaml

clean:
	rm -f uec_console

.PHONY: all test clean
