CC=gcc
CFLAGS=-Wall
LIBS=

all: clean ifx_fw_extract

ifx_fw_extract: ifx_fw_extract.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean

clean:
	rm -f *.o ifx_fw_extract
