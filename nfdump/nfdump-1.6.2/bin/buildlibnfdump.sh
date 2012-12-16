#!/bin/bash
rm libnfdump.so
rm libnfdump.o
rm testlibnfdump
gcc -Wall -fPIC -c libnfdump.c -I ../ -ggdb
gcc -shared -Wl,-soname,libnfdump.so -o libnfdump.so  libnfdump.o nffile.o flist.o util.o minilzo.o nfx.o -lc
gcc -o testlibnfdump testlibnfdump.c -ldl

