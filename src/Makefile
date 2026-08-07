CXX      = g++
CXXFLAGS = -Wall -Wextra -O3 -std=c++17

SRCS    = SmallScaleAES.cpp distinguisher_lib.cpp key_recovery_lib.cpp
T_COR   = test_correctness
B_PERF  = bench_perf

.PHONY: all test bench clean

all: $(T_COR) $(B_PERF)

$(T_COR): $(SRCS) test_correctness.cpp distinguisher.h key_recovery.h SmallScaleAES.h
	$(CXX) $(CXXFLAGS) -o $@ $(SRCS) test_correctness.cpp

$(B_PERF): $(SRCS) bench_perf.cpp distinguisher.h key_recovery.h SmallScaleAES.h
	$(CXX) $(CXXFLAGS) -o $@ $(SRCS) bench_perf.cpp

test: $(T_COR)
	@echo ""; ./$(T_COR)

bench: $(B_PERF)
	@echo ""; ./$(B_PERF)

clean:
	rm -f $(T_COR) $(B_PERF) *.o

distclean: clean
	rm -f DifferentialDistinguisher KeyRecovery_Modified_Simple
