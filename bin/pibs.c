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

void process_frame(pibs_t* pibs, wtap *wth,
                   uint8_t *eth)
{
    struct ip* ipv4;
    struct tcphdr* tcp;
    unsigned char* buf;
    size_t length;

    buf = eth+14;
    length = wth->rec.rec_header.packet_header.caplen-14;

    if (length < sizeof(struct ip)) {
        return;
    }


    ipv4 =  (struct ip*)buf;
    // Focus only on TCP packets
    if (ipv4->ip_p != 6)
        return;

    tcp = (struct tcphdr*)(buf+sizeof(struct ip));

    synseen_process_frame(pibs, wth, eth, ipv4, tcp);

    //Put other frame processing activities here
}

void process_file(pibs_t* pibs)
{
    wtap *wth;
    int err;
    char *errinfo;
    gint64 data_offset;
    int ethertype;
    guint8 *buf;

    fprintf(stderr,"Processing %s\n",pibs->filename);
    wth = wtap_open_offline ( pibs->filename, WTAP_TYPE_AUTO, (int*)&err,
                             (char**)&errinfo, FALSE);
    if (wth) {
        /* Loop over the packets and adjust the headers */
        while (wtap_read(wth, &err, &errinfo, &data_offset)) {
            if (wth->rec.rec_type == REC_TYPE_PACKET) {
                if (wth->rec.tsprec == WTAP_TSPREC_USEC){
                    if (wth->rec.rec_header.packet_header.caplen < 14) {
                        fprintf(stderr,"Packet too small, skip\n");
                        continue;
                    }
                }
                buf = wth->rec_data->data;
                ethertype = buf[12] << 8 | buf[13];
                // TODO Focus on IPv4 only
                if (ethertype == 0x0800) {
                    process_frame(pibs, wth, buf);
                }
            }
        }
        wtap_close(wth);
	fprintf(stderr,"[INFO] Processing of filename %s done\n",pibs->filename);
    }else{
        fprintf(stderr, "[ERROR] Could not open filename %s,cause=%s\n",pibs->filename,
                wtap_strerror(err));
    }
}

pibs_t* init(void)
{
    pibs_t *pibs;

    wtap_init(FALSE);
    pibs=calloc(sizeof(pibs_t),1);
    //TODO check if size is correct
    pibs->data_size = sizeof(pibs_header_t) + NBINSCALE * NBINS * SZBIN * NBINITEMS * sizeof(item_t);
    pibs->data = calloc(pibs->data_size,1);
    pibs->filename = calloc(FILENAME_MAX,1);
    pibs->uuid = calloc(SZUUID,1);
    pibs->key = calloc(SZKEY,1);
    pibs->server = calloc(SZSERVER,1);
    printf("#Internal look up structure size in bytes: %ld\n",  pibs->data_size);
    // Build header
    pibs->data[0]='P';
    pibs->data[1] = 'I';
    pibs->data[2] = 'B';
    pibs->data[3] = 'S';
    pibs->data[4] = 1; //version 1
    pibs->next_block = sizeof(pibs_header_t);
    pibs->bin_offset = pibs->next_block;
    printf("#data address is %p\n",pibs->data);
    pibs->bin_table = (uint32_t*)(pibs->data+pibs->bin_offset);
    printf("#bin_table address is %p\n", pibs->bin_table);
    // Create bins
    pibs->next_block+=SZBIN * NBINS;
    printf("#next block %d\n", pibs->next_block);
    pibs->items = (item_t*)(pibs->data+pibs->next_block);
    pibs->next_item = 0;
    printf("#items are address %p\n", pibs->items);
    pibs->max_item = NBINS * NBINITEMS;
    printf("#max_item: %d\n", pibs->max_item);
    return pibs;
}

void process_redis_list(pibs_t* pibs)
{
    redisReply *reply;
    int rtype;
    snprintf(pibs->key, SZKEY, "analyzer:1:%s",pibs->uuid);
    pibs->ctx = redisConnect(pibs->server, pibs->port);
    if (pibs->ctx != NULL) {
        if (pibs->redisdb >0)   {
            printf("[INFO] Select redis database %d\n", pibs->redisdb);
            reply = redisCommand(pibs->ctx, "SELECT %d", pibs->redisdb);
            if (reply) {
                rtype = reply->type;
                freeReplyObject(reply);
                if (rtype != REDIS_REPLY_STATUS) {
                    printf("[ERROR] Cannot switch to database %d. Abort.",
                            pibs->redisdb);
                    return;
                }
            }
        }
        do {
            reply = redisCommand(pibs->ctx,"RPOP %s", pibs->key);
            if (reply) {
                rtype = reply->type;
                if (rtype == REDIS_REPLY_STRING ) {
                     printf("#Need to proces file %s\n", reply->str);
                     strncpy(pibs->filename,  reply->str, FILENAME_MAX);
                     process_file(pibs);
                }
                freeReplyObject(reply);
            }
        } while (rtype != REDIS_REPLY_NIL);
    } else {
        if (pibs->ctx->errstr) {
            fprintf(stderr,  "Cannot connect to redis. Cause=%s\n",pibs->ctx->errstr);
        }
    }
}


int main(int argc, char* argv[])
{

    int opt;
    pibs_t* pibs;

    pibs  = init();

    fprintf(stderr, "[INFO] pid = %d\n",(int)getpid());

    while ((opt = getopt(argc, argv, "r:dbsni:au:z:p:w:y:")) != -1) {
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
