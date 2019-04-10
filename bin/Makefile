pibs:		pibs.o memutils.o synseen.o
	gcc -Wall -o pibs pibs.o memutils.o synseen.o -lwiretap `pkg-config --libs glib-2.0` -lpcap -lhiredis -ggdb

memutils.o:	memutils.c
	gcc -Wall -c memutils.c  `pkg-config --cflags glib-2.0` -I /usr/include/wireshark/wiretap -I /usr/include/wireshark/wsutil -I /usr/include/wireshark `pkg-config --libs glib-2.0` -I /usr/local/include/hiredis -ggdb

synseen.o:	synseen.c
	gcc -D HASHDEBUG=0 -Wall -c synseen.c  `pkg-config --cflags glib-2.0` -I /usr/include/wireshark/wiretap -I /usr/include/wireshark/wsutil -I /usr/include/wireshark `pkg-config --libs glib-2.0` -I /usr/local/include/hiredis -ggdb

pibs.o:	pibs.c
	gcc -D HASHDEBUG=0 -Wall -c pibs.c `pkg-config --cflags glib-2.0` -I /usr/include/wireshark/wiretap -I /usr/include/wireshark/wsutil -I /usr/include/wireshark `pkg-config --libs glib-2.0` -I /usr/local/include/hiredis -ggdb

clean:
	-rm pibs
	-rm *.o
