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
#define __USE_XOPEN
#include <time.h>
#include "pibs.h"
#include <gmodule.h>

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

char* create_path(pibs_t* pibs, uint16_t port, uint64_t ts)
{
    struct tm tm;
    char  s[32];
    char *out;
    out = calloc(1,FILENAME_MAX);
    if (out) {
        snprintf(s,32,"%ld",ts);
        if (strptime(s,"%s",&tm)){
            strftime((char*)&s,32,"%Y-%m-%d", &tm);
            //TODO use date sub-directory in case of too many files
            snprintf(out, 2*FILENAME_MAX, "%s/%d/%s.txt",pibs->outputfile,port,s);
            return out;
        }
    }
    //Something went wrong
    return NULL;
}

//FIXME avoid mem allocation functions for each packet do them globaly per file
void frame_to_bgpr(pibs_t* pibs, wtap *wth, uint8_t* eth,
struct ip* ipv4, struct tcphdr* tcp)
{
    char *dirname;
    dirname = create_path(pibs, ntohs(tcp->th_sport), wth->rec.ts.secs);
    if (dirname) {
        printf("%s\n", dirname);
        free(dirname);
    }
}

gint cmp_ips(gconstpointer a, gconstpointer b)
{
    uint32_t* x;
    uint32_t* y;
    x = (uint32_t*)a;
    y = (uint32_t*)b;
    return *x<*y;
}

int main(int argc, char* argv[])
{
    pibs_t* pibs;
    int opt;
    GTree *ip_tree;
    pibs  = init();
    uint32_t *y;
    ip_tree = NULL;

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
            case 'd':
                strncpy((char*)&(pibs->outputfile), optarg, FILENAME_MAX);
                pibs->outputfile[FILENAME_MAX-1]  = '\0';
                break;
        }
    }

    //sorted array insert operations -> o(n) not good if we have a lot of inserts
    //Problem: memalloc per each ip address
    //Problem: duplicates are added

    // Gtree insert IP value several times
     
    y = calloc(1,sizeof(uint32_t));
    *y = 34;
//    ip_list = g_list_insert_sorted_with_data (ip_list,y,&cmp_ips,NULL);
//    y = calloc(1,sizeof(uint32_t));
//    *y = 34;
//    ip_list = g_list_insert_sorted_with_data (ip_list,y,&cmp_ips,NULL);
//    y = calloc(1,sizeof(uint32_t));
//    *y = 99;
//    ip_list = g_list_insert_sorted_with_data (ip_list,y,&cmp_ips,NULL);


    return EXIT_SUCCESS;
    //Set call back function
    pibs->synseen_callback = &frame_to_bgpr;

    if (pibs->filename[0]) {
        process_file(pibs);
    }

    return EXIT_SUCCESS;
}
