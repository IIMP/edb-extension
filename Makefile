.PHONY: clean install

ENCLAVE := enclave/edb_enclave.signed.so

EDB = edb.so

EDB_MAKEFILE = edb.mk

all: $(EDB)

$(ENCLAVE):
	$(MAKE) -C enclave

$(EDB): $(ENCLAVE)
	$(MAKE) -f $(EDB_MAKEFILE)

clean:
	$(MAKE) -C enclave clean
	$(MAKE) -f $(EDB_MAKEFILE) clean

install:
	$(MAKE) -f $(EDB_MAKEFILE) install
