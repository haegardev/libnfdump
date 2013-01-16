nfstorage:	nfstorage.o
	gcc -o nfstorage nfstorage.o -ggdb -lnfdump `pkg-config --libs glib-2.0` 

nfstorage.o:	nfstorage.c
	gcc -Wall -c nfstorage.c -ggdb `pkg-config --cflags glib-2.0`

clean:
	rm nfstorage
	rm nfstorage.o


