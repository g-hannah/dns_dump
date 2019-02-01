CC=gcc
WFLAGS=-Wall -Werror
CFILES=main.c dns_dump.c conversion.c encode.c results.c axfr.c remove_duplicate_soa_records.c trace.c records.c misc.c memory.c logging.c
OFILES=main.o dns_dump.o conversion.o encode.o results.o axfr.o remove_duplicate_soa_records.o trace.o records.o misc.o memory.o logging.o

LIBS=-lcrypto

dns_dump: $(OFILES)
	$(CC) -g $(WFLAGS) -o dns_dump $(OFILES) $(LIBS)

$(OFILES): $(CFILES)
	$(CC) -g -c $(WFLAGS) $(CFILES) $(LIBS)

clean:
	rm *.o
