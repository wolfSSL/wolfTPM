CC=gcc
CFLAGS=-Wall
LIBS=

all: ifx_fw_extract

ifx_fw_extract: ifx_fw_extract.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean

clean:
	rm -f *.o signature
