/*
* pibs - Passive Identification of BackScatter
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
#include "pibs.h"

void usage(void)
{
    printf("Usage: pibs [OPTION] ...\n");
    printf("Identify backscatter in pacp files\n");
    printf("\nOPTIONS\n");
    printf("\n    -n Create new shared memory segment data structure\n");
    printf("\n    -i Write shared segment identifier in a file.\n");
    printf("       This option must be used in conjuntion with -n option\n");
    printf("      -r read pcap files and identity potential backscatter traffic\n");
    printf("      -b Show potential backscatter on stdout. The be used in conjuntion with -r\n");
}

int main(int argc, char* argv[])
{

    int opt;
    pibs_t* pibs;

    pibs  = init();

    fprintf(stderr, "[INFO] pid = %d\n",(int)getpid());

    while ((opt = getopt(argc, argv, "r:dbsni:au:z:p:w:y:h")) != -1) {
        switch (opt) {
            case 'r':
                strncpy(pibs->filename, optarg, FILENAME_MAX);
                break;
            case 'd':
                pibs->should_dump_table = 1;
                break;
            case 'b':
                pibs->show_backscatter = 1;
                break;
            case 's':
                pibs->show_stats = 1;
                break;
            case 'n':
                pibs->should_create_shm = 1;
                break;
            case 'i':
                strncpy(pibs->shmid_file, optarg, FILENAME_MAX);
                break;
            case 'a':
                pibs->should_attach = 1;
                break;
            case 'u':
                strncpy(pibs->uuid, optarg, SZUUID);
                break;
            case 'z':
                strncpy(pibs->server,optarg, SZSERVER);
                break;
            case 'p':
                pibs->port=atoi(optarg);
                break;
            case 'w':
                strncpy(pibs->outputfile,optarg, FILENAME_MAX);
                pibs->should_writepcap = 1;
                break;
            case 'y':
                pibs->redisdb = atoi(optarg);
                break;
            case 'h':
                usage();
                break;
            default: /* '?' */

                fprintf(stderr, "[ERROR] Invalid command line was specified\n");
        }
    }
    if (pibs->should_create_shm) {
        pibs_shmget(pibs);
        if (pibs->shmid >0){
            printf("Create a new shared memory segment %d\n", pibs->shmid);
        } else {
            printf("Failed to get shared memory segment. Cause = %s\n",
                    strerror(pibs->errno_copy));
        }
    }
    if (pibs->should_attach) {
        if (pibs_shmat(pibs) > 0 ) {
            printf("Attached to shared memory segment %d\n", pibs->shmid);
        } else {
            printf("Failed to attach to shared memory segment. System error:%s\n",
                    strerror(pibs->errno_copy));
            return EXIT_FAILURE;
        }
    }
    if (pibs->uuid[0]) {
        if ((pibs->server[0] == 0) || (pibs->port == 0)) {
            fprintf(stderr,"Redis parameter server and port are incomplete. Use -z and -p options.\n");
            return EXIT_FAILURE;
        }
        process_redis_list(pibs);
    }

    //FIXME Add proper error handling for writecap
    if (pibs->should_writepcap) {
        pibs->outcap = pcap_open_dead(DLT_EN10MB, 65535);
        pibs->dumper = pcap_dump_open(pibs->outcap, pibs->outputfile);
        if (pibs->dumper == NULL) {
            printf("Failed to open outputfile. Reason=%s\n",  pcap_geterr(pibs->outcap));
            return EXIT_FAILURE;
        }
    }

    if (pibs->show_backscatter)
        printf("#timestamp, source IP, TCP flags, source port\n");
    if (pibs->filename[0]) {
        process_file(pibs);
    }
    if (pibs->should_dump_table){
        pibs_dump_raw(pibs);
        pibs_dump_raw(pibs);
    }
    if (pibs->show_stats){
        pibs_dump_stats(pibs);
    }
    if (pibs->should_writepcap) {
        pcap_dump_close(pibs->dumper);
        printf("[INFO] Created pcap file %s\n", pibs->outputfile);
    }
    return EXIT_FAILURE;
}
