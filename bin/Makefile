all:	pibs pibs-stat pibs-BGP-Ranking pibs-isn

pibs-stat:	pibs-stat.o libpibs.o memutils.o synseen.o
	gcc -Wall -o pibs-stat pibs-stat.o libpibs.o memutils.o synseen.o -lwiretap `pkg-config --libs glib-2.0` -lpcap -lhiredis -ggdb


pibs-stat.o:	pibs-stat.c
	gcc -D HASHDEBUG=0 -Wall -c pibs-stat.c  `pkg-config --cflags glib-2.0` -I /usr/include/wireshark/wiretap -I /usr/include/wireshark/wsutil -I /usr/include/wireshark `pkg-config --libs glib-2.0` -I /usr/local/include/hiredis -ggdb

pibs-isn:	pibs-isn.o libpibs.o memutils.o synseen.o
	gcc -Wall -o pibs-isn pibs-isn.o libpibs.o memutils.o synseen.o -lwiretap `pkg-config --libs glib-2.0` -lpcap -lhiredis -ggdb

pibs-stat.o:	pibs-isn.c
	gcc -D HASHDEBUG=0 -Wall -c pibs-isn.c  `pkg-config --cflags glib-2.0` -I /usr/include/wireshark/wiretap -I /usr/include/wireshark/wsutil -I /usr/include/wireshark `pkg-config --libs glib-2.0` -I /usr/local/include/hiredis -ggdb

pibs-BGP-Ranking:	pibs pibs-BGP-Ranking.o libpibs.o memutils.o synseen.o
	gcc -Wall -o pibs-BGP-Ranking pibs-BGP-Ranking.o libpibs.o memutils.o synseen.o -lwiretap `pkg-config --libs glib-2.0` -lpcap -lhiredis -ggdb

pibs-BGP-Ranking.o:	pibs-BGP-Ranking.c
	gcc -D HASHDEBUG=0 -Wall -c pibs-BGP-Ranking.c `pkg-config --cflags glib-2.0` -I /usr/include/wireshark/wiretap -I /usr/include/wireshark/wsutil -I /usr/include/wireshark `pkg-config --libs glib-2.0` -I /usr/local/include/hiredis -ggdb

pibs:		pibs.o memutils.o synseen.o libpibs.o
	gcc -Wall -o pibs pibs.o memutils.o synseen.o libpibs.o -lwiretap `pkg-config --libs glib-2.0` -lpcap -lhiredis -ggdb

libpibs.o:	libpibs.c
	gcc -D HASHDEBUG=0 -Wall -c libpibs.c `pkg-config --cflags glib-2.0` -I /usr/include/wireshark/wiretap -I /usr/include/wireshark/wsutil -I /usr/include/wireshark `pkg-config --libs glib-2.0` -I /usr/local/include/hiredis -ggdb


memutils.o:	memutils.c
	gcc -Wall -c memutils.c  `pkg-config --cflags glib-2.0` -I /usr/include/wireshark/wiretap -I /usr/include/wireshark/wsutil -I /usr/include/wireshark `pkg-config --libs glib-2.0` -I /usr/local/include/hiredis -ggdb

synseen.o:	synseen.c
	gcc -D HASHDEBUG=0 -Wall -c synseen.c  `pkg-config --cflags glib-2.0` -I /usr/include/wireshark/wiretap -I /usr/include/wireshark/wsutil -I /usr/include/wireshark `pkg-config --libs glib-2.0` -I /usr/local/include/hiredis -ggdb

pibs.o:	pibs.c
	gcc -D HASHDEBUG=0 -Wall -c pibs.c `pkg-config --cflags glib-2.0` -I /usr/include/wireshark/wiretap -I /usr/include/wireshark/wsutil -I /usr/include/wireshark `pkg-config --libs glib-2.0` -I /usr/local/include/hiredis -ggdb

clean:
	-rm pibs
	-rm pibs-stat
	-rm pibs-BGP-Ranking
	-rm *.o
