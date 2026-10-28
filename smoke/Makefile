CXX ?= g++
CXXFLAGS ?= -std=c++14 -O2 -Wall -Wextra -I../include
SYSTEMC_HOME ?= /opt/tools/systemc2.34
SCFLAGS = -I$(SYSTEMC_HOME)/include
SCLIBS  = -L$(SYSTEMC_HOME)/lib-linux64 -lsystemc -lpthread
MODEL   = -L../lib -luec_model

all: tb_uec_smoke tb_uec_tss_smoke tb_uec_switch_smoke

tb_uec_smoke: tb_uec_smoke.cpp
	$(CXX) $(CXXFLAGS) $< -o $@

tb_uec_tss_smoke: tb_uec_tss_smoke.cpp
	$(CXX) $(CXXFLAGS) $< $(MODEL) -lcrypto -o $@

tb_uec_switch_smoke: tb_uec_switch_smoke.cpp
	$(CXX) $(CXXFLAGS) $(SCFLAGS) $< $(MODEL) $(SCLIBS) -o $@

red: tb_uec_tss_red
tb_uec_tss_red: tb_uec_tss_red.cpp
	$(CXX) $(CXXFLAGS) -DUET_TSS_RED_NOTAG $< -lcrypto -o $@

test: all
	./tb_uec_smoke
	./tb_uec_tss_smoke
	LD_LIBRARY_PATH=$(SYSTEMC_HOME)/lib-linux64 ./tb_uec_switch_smoke

clean:
	rm -f tb_uec_smoke tb_uec_tss_smoke tb_uec_switch_smoke tb_uec_tss_red

.PHONY: all red test clean
