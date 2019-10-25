CC=gcc
WFLAGS=-Wall -Werror
LIBS=-lcrypto

SOURCE_FILES := \
	main.c \
	dns_dump.c \
	conversion.c \
	encode.c \
	axfr.c \
	misc.c \
	memory.c \
	logging.c

OBJECT_FILES := ${SOURCE_FILES:.c=.o}

dns_dump: $(OBJECT_FILES)
	$(CC) -g $(WFLAGS) -o dns_dump $(OBJECT_FILES) $(LIBS)

$(OBJECT_FILES): $(SOURCE_FILES)
	$(CC) -g -c $(WFLAGS) $(SOURCE_FILES) $(LIBS)

clean:
	rm *.o
