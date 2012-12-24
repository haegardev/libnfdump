portevolution:	portevolution.o
	gcc -o portevolution portevolution.o -ggdb -lnfdump `pkg-config --libs glib-2.0` 

portevolution.o:	portevolution.c
	gcc -Wall -c portevolution.c -ggdb `pkg-config --cflags glib-2.0`

clean:
	rm portevolution
	rm portevolution.o


