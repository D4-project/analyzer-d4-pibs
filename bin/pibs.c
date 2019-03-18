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
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <assert.h>
#include <string.h>
#include <pcap/pcap.h>
#include <wtap.h>
#include <wtap-int.h>
#include <unistd.h>
#include <signal.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <errno.h>

#include <hiredis/hiredis.h>

//TODO test other values
#define NBINS 1024 //Number of bins
#define NBINITEMS 255 //Number of items per bin
#define SZBIN 4
#define SZUUID 40
#define SZKEY 1024
#define SZSERVER 1024
#define NBINSCALE 2 // Scaling factor of the entire datastructure

#define HDBG(...) if (HASHDEBUG) fprintf(stderr, __VA_ARGS__)

#define ERR_ATTACH_NOT_EMPTY 11
#define ERR_NO_SHMID_FILE 12

typedef struct pibs_header_s {
    uint8_t magic [4];
    uint8_t version;
    //Put some useful stuff here
    uint32_t next_item;
    uint32_t bin_offset;
    uint64_t data_size;
    uint32_t max_item;
    uint8_t padding [3];
} pibs_header_t;


/* TODO This can squezed. Timestamp can be expressed on 8 bits i.e. relative
 * minutes
 * IP can be represented with 16 bits ipaddr = ip / bin_size
 * Not sure if space can be saved in usual cases
 */
typedef struct item_s {
    uint32_t timestamp;
    uint32_t next_item;
    uint32_t ipaddr;
} item_t;

/* Need to hash source IP addresses and record first seen and flags */
typedef struct pibs_s {
    int errno_copy;
    int errno_pibs;
    char *filename;
    char *uuid;
    char *key;
    char *server;
    uint16_t port;
    redisContext *ctx;
    int should_dump_table;
    int show_backscatter;
    int show_stats;
    int should_create_shm;
    int should_attach;
    //TODO use self contained data structure that can be easily serialized
    //Put data structure in an entire block to easier serialize
    uint8_t *data;
    uint32_t next_block;
    uint32_t next_item;
    uint32_t bin_offset;
    uint64_t data_size;
    uint32_t* bin_table;
    uint32_t max_item;
    item_t* items;
    int shmid;
    char shmid_file [FILENAME_MAX];
} pibs_t;

int load_shmid_file(pibs_t* pibs)
{
    FILE* fp;
    if (pibs->shmid_file[0]) {
        fp = fopen(pibs->shmid_file,"r");
        if (fp) {
            //FIXME check file
            fscanf(fp, "%d", &pibs->shmid);
            return pibs->shmid;
        }
    } else {
        pibs->errno_pibs = ERR_NO_SHMID_FILE;
    }
    return -1;
}

//TODO when attaching the next_item  must be recovered if results
//of previous runs need to be increased
int pibs_shmat(pibs_t* pibs)
{
    /* FIXME  init function needs to break up in two functions. One that
     *       initializes internal pibs structures as cli options etc
     *       a second one for describing the data itself, size of bin_table
     *       number of items etc.
     */
    if (pibs->data) {
        free(pibs->data);
        pibs->data = NULL;
    }
    if (pibs->data) {
        pibs->errno_pibs =  ERR_ATTACH_NOT_EMPTY;
        printf("TEST Data is not null\n");
        return -1;
    }
    if (!pibs->shmid_file[0]) {
        pibs->errno_pibs = ERR_NO_SHMID_FILE;
        return -1;
    }
    if (load_shmid_file(pibs) > 0) {
            pibs->data = shmat(pibs->shmid, NULL, SHM_RND);
        if ( (int) pibs->data == -1) {
            pibs->errno_copy = errno;
        } else {
            return 1;
        }
    }
    // Something did not work
    return -1;
}

int pibs_shmget(pibs_t* pibs)
{
    FILE* fp;
    pibs->shmid = shmget(IPC_PRIVATE, pibs->data_size, IPC_CREAT |  0600);
    if (pibs->shmid < 0) {
        pibs->errno_copy = errno;
    }

    if (pibs->shmid_file[0]){
            fp = fopen(pibs->shmid_file, "w");
            if (fp) {
                fprintf(fp,"%d",pibs->shmid);
                fclose(fp);
            }
            //TODO error handling
    }
    //TODO attach to it and bzero it
    //setup the tables
    return pibs->shmid;
}

/*
 * Returns -1 if not found
 * returns last timestamp if found
 */
int_fast64_t get_last_timestamp(pibs_t* pibs, uint32_t ip)
{
    uint32_t idx;
    uint32_t i;
    //TODO explore alternative hashing functions
    //https://stackoverflow.com/questions/664014/what-integer-hash-function-are-good-that-accepts-an-integer-hash-key/12996028#12996028
    idx = ip % NBINS;
    HDBG("[TS] Checking for IP %x at index = %d\n", ip, idx);
    i = pibs->bin_table[idx];
    while (i){
        if (pibs->items[i].ipaddr == ip) {
            HDBG("[TS] Found item %x at position %d\n", ip , i);
                return pibs->items[i].timestamp;
            }
        i = pibs->items[i].next_item;
    }
    HDBG("[TS] IP: %x was not found return -1\n",ip);
    return -1;
}

void insert_ip(pibs_t* pibs, uint32_t ip, uint32_t ts)
{
    uint32_t idx;
    uint32_t i;
    uint32_t parent;

    idx = ip  % NBINS;
    HDBG("[INS] Lookup IP address %x. Hashed value: %d\n", ip, idx);
    parent = 0;
    if (pibs->bin_table[idx]){
        // There is already someone in the bin
        i = pibs->bin_table[idx];
        HDBG("[INS] Starting searching at position %d\n", i);
        do {
            HDBG("[INS] Iterating items at index %d. Current position: %d.\
                  Next position = %d\n",
                 idx,i,pibs->items[i].next_item);
            HDBG("[INS] Checking IP at address %p\n",&pibs->items[i]);
            if (pibs->items[i].ipaddr == ip) {
               HDBG("[INS] Found item %x at position %d\n", ip , i);
               HDBG("[INS] New timestamp for ip %x is %d\n",ip,ts);
               pibs->items[i].timestamp = ts;
               return;
            }
            parent = i;
            i = pibs->items[i].next_item;
        } while (i != 0 );
        HDBG("[INS] The IP %x was not found in the item list, last parent %d\n",
              ip, parent);
    }
    // The IP was not found in an item list or the hashed value wsa not present
    // in the bin table, so create a new item
    pibs->next_item++;
    if (pibs->next_item > pibs->max_item) {
        printf("FIXME run out of memory. Do something better than abort\n");
        //Go through old timestamps and keep linked list of stuff that can be
        //reused or do kind of defragmentation
        abort();
    }
    if (pibs->bin_table[idx] == 0) {
        pibs->bin_table[idx] = pibs->next_item;
    }
    HDBG("[INS] Insert ip %x at position %d, parent = %d\n", ip,
         pibs->next_item,parent);
    pibs->items[pibs->next_item].ipaddr = ip;
    pibs->items[pibs->next_item].timestamp = ts;
    if (parent) {
        pibs->items[parent].next_item = pibs->next_item;
    }
}

void process_frame(pibs_t* pibs, wtap *wth,
                   uint8_t *buf, size_t length)
{
    struct ip* ipv4;
    uint32_t ip;
    struct tcphdr* tcp;
    int_fast64_t lastseen;

    if (length < sizeof(struct ip)) {
        return;
    }


    ipv4 =  (struct ip*)buf;
    // Focus only on TCP packets
    if (ipv4->ip_p != 6)
        return;

    tcp = (struct tcphdr*)(buf+sizeof(struct ip));

    memcpy(&ip, &ipv4->ip_src, 4);
    // Record only source ips where syn flag is set
    // TODO check other connection establishment alternatives
    if (tcp->th_flags  == 2 ){
        insert_ip(pibs, ip, wth->rec.ts.secs);
        return;
    }

    lastseen =  get_last_timestamp(pibs, ip);

    if (lastseen > 0){
        HDBG("IP %x %s was already seen before at %ld. Time difference %ld.\n"
               , ip, inet_ntoa(ipv4->ip_src), lastseen, wth->rec.ts.secs-lastseen);
        return;
    }
    // TODO keep these IPs in a hashtable and rank them
    if (pibs->show_backscatter) {
        printf("%s,%d,%d\n",
               inet_ntoa(ipv4->ip_src), tcp->th_flags, ntohs(tcp->th_sport));
    }
    //TODO relative time
    //Purge old ips?
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
                    process_frame(pibs, wth, buf+14, wth->rec.rec_header.packet_header.caplen -14);
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

void pibs_dump_raw(pibs_t* pibs)
{
    int i;
    printf("#RAW table dump\n");
    printf("#Index next_item\n");
    printf("#BINs\n");
    for (i=0; i< NBINS; i++) {
        printf("%d  %d\n", i, pibs->bin_table[i]);
    }
    printf("#ITEMS\n");
    printf("#Index next_item, timestamp, ipaddr\n");
    for (i=0; i < NBINITEMS * NBINS; i++) {
        printf("%d %d %d %x\n", i, pibs->items[i].next_item,
                                 pibs->items[i].timestamp,
                                 pibs->items[i].ipaddr);
    }
}

void pibs_dump_stats(pibs_t* pibs)
{
    int i;
    int j;
    int cnt;
    uint64_t sum;
    sum = 0;
    printf("#Bin table\n");
    printf("#Bin number, Item offset, number of items\n");
    for (i=0; i < NBINS; i++) {
        j= pibs->bin_table[i];
        cnt = 0;
        while (j) {
            cnt++;
            j=pibs->items[j].next_item;
        }
        sum+=cnt;
        printf("%d %d %d\n", i, pibs->bin_table[i], cnt);
    }
    printf("#Number of unique IP addresses: %ld\n", sum);
}

void process_redis_list(pibs_t* pibs)
{
    redisReply *reply;
    int rtype;
    snprintf(pibs->key, SZKEY, "analyzer:1:%s",pibs->uuid);
    pibs->ctx = redisConnect(pibs->server, pibs->port);
    if (pibs->ctx != NULL) {
        do {
            reply = redisCommand(pibs->ctx,"LPOP %s", pibs->key);
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

    while ((opt = getopt(argc, argv, "r:dbsni:au:z:p:")) != -1) {
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
    if (pibs->show_backscatter)
        printf("#source IP, TCP flags, source port\n");
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
    return EXIT_FAILURE;
}
