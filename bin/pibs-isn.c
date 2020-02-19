/*
* pibs - Create lists of isn having the same value than ip address
*
* Copyright (C) 2020 Gerard Wagener
* Copyright (C) 2020 CIRCL Computer Incident Response Center Luxembourg
* (SMILE gie).
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU Affero General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
*/
#include <stdio.h>
#define __USE_XOPEN
#include <time.h>
#include "pibs.h"

void usage(void)
{
    printf("Create lists of targets under SYN floods for BGP Ranking\n");
    printf("\n");
    printf("OPTIONS\n");
    printf("    -h Shows this screen\n");
    printf("    -r inputfile\n");
    printf("       Read pcap file from inputfile\n");
    printf("\n");
    printf("DIRECTORY STRUCTURE\n");
    printf("<directory>/port/year/month/year-month-day.txt\n");
}

void process(pibs_t* pibs, wtap *wth, uint8_t* eth,
struct ip* ipv4, struct tcphdr* tcp)
{
    if (ipv4->ip_dst.s_addr == tcp->seq) {
        printf("%x\n",ntohl(tcp->seq));
    }
}

int main(int argc, char* argv[])
{
    pibs_t* pibs;
    int opt;
    pibs  = init();

    while ((opt = getopt(argc, argv, "hr:d:")) != -1) {
        printf("%d\n", opt);
        switch (opt) {
            case 'h':
                usage();
                break;
            case 'r':
                strncpy(pibs->filename, optarg, FILENAME_MAX);
                pibs->filename[FILENAME_MAX-1] = '\0';
                break;
        }
    }

    //Set call back function
    pibs->synseen_callback = &process;

    if (pibs->filename[0]) {
        process_file(pibs);
    }

    return EXIT_SUCCESS;
}
