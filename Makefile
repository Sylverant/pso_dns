# *nix Makefile.
# Should build with any standardish C99-supporting compiler.

all: pso_dns

pso_dns:
	$(CC) -o pso_dns pso_dns.c

.PHONY: clean

clean:
	-rm -fr pso_dns *.o *.dSYM
