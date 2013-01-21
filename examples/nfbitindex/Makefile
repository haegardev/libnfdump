nf-bitindex:	nf-bitindex.o
	gcc -o nf-bitindex nf-bitindex.o -ggdb -lnfdump `pkg-config --libs glib-2.0` -lz

nf-bitindex.o:	nf-bitindex.c
	gcc -Wall -c nf-bitindex.c -ggdb `pkg-config --cflags glib-2.0`

clean:
	rm nf-bitindex
	rm nf-bitindex.o


