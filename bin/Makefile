pibs:		pibs.o
	gcc -Wall -o pibs pibs.o -lwiretap `pkg-config --libs glib-2.0` -lpcap -lhiredis -ggdb
pibs.o:	pibs.c
	gcc -D HASHDEBUG=0 -Wall -c pibs.c `pkg-config --cflags glib-2.0` -I /usr/include/wireshark/wiretap -I /usr/include/wireshark/wsutil -I /usr/include/wireshark `pkg-config --libs glib-2.0` -I /usr/local/include/hiredis -ggdb

clean:
	-rm pibs
	-rm *.o
