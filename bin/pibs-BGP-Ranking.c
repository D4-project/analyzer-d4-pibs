/*
* pibs - Create lists of targets under SYN floods for bgp ranking
*
* Copyright (C) 2019 Gerard Wagener
* Copyright (C) 2019 CIRCL Computer Incident Response Center Luxembourg
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
#include "pibs.h"

void usage(void)
{
    printf("Create lists of targets under SYN floods for BGP Ranking\n");
    printf("\n");
    printf("OPTIONS\n");
    printf("    -h Shows this screen\n");
    printf("    -r inputfile\n");
    printf("       Read pcap file from inputfile\n");
    printf("    -d directory\n");
    printf("       Root directory where the list should be stored\n");
    printf("\n");
    printf("DIRECTORY STRUCTURE\n");
    printf("<directory>/port/year/month/year-month-day.txt\n");
}

void frame_to_bgpr(pibs_t* pibs, wtap *wth, uint8_t* eth,
struct ip* ipv4, struct tcphdr* tcp)
{
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
                break;
        }
    }

    //Set call back function
    pibs->synseen_callback = &frame_to_bgpr;

    if (pibs->filename[0]) {
        process_file(pibs);
    }

    return EXIT_SUCCESS;
}
