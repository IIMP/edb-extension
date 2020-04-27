MODULE_big = edb
EXTENSION = edb
DATA = edb--0.1.sql
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)

ENCLAVE_FILENAME := $(realpath .)/enclave/edb_enclave.signed.so

SGX_SDK ?= /opt/intel/sgxsdk
SGX_COMMON_FLAGS += -Wall -Wextra -Winit-self -Wpointer-arith -Wreturn-type \
                    -Waddress -Wsequence-point -Wformat-security \
                    -Wmissing-include-dirs -Wfloat-equal -Wundef -Wshadow \
                    -Wcast-align -Wcast-qual -Wconversion -Wredundant-decls \
					-D ENCLAVE_FILENAME=\"$(ENCLAVE_FILENAME)\" -D DEBUG_MODE

SGX_COMMON_CFLAGS := $(SGX_COMMON_FLAGS) -Wjump-misses-init -Wstrict-prototypes -Wunsuffixed-float-constants -std=c11
SGX_COMMON_CXXFLAGS := $(SGX_COMMON_FLAGS) -Wnon-virtual-dtor -std=c++11

PG_CFLAGS = $(SGX_COMMON_CFLAGS) -O2 -I$(SGX_SDK)/include -Iinclude
PG_CXXFLAGS = $(SGX_COMMON_CXXFLAGS) -O2 -I$(SGX_SDK)/include -Iinclude
PG_LDFLAGS = -L$(SGX_SDK)/lib64
SHLIB_LINK = -lstdc++ -lsgx_urts

EDB_CPP_FILES := $(wildcard *.cpp) $(wildcard internal/*.cpp)

OBJS = $(EDB_CPP_FILES:.cpp=.o) enclave/bridge/enclave_u.o

override with_llvm=no

include $(PGXS)
