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
#ifndef _PIBS_H_
#define PIBS

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
    int should_writepcap;
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
    char outputfile[FILENAME_MAX];
    pcap_dumper_t* dumper;
    pcap_t* outcap;
    uint32_t redisdb;
} pibs_t;

int load_shmid_file(pibs_t* pibs);
int pibs_shmat(pibs_t* pibs);
int pibs_shmget(pibs_t* pibs);
int_fast64_t get_last_timestamp(pibs_t* pibs, uint32_t ip);
void insert_ip(pibs_t* pibs, uint32_t ip, uint32_t ts);
void process_frame(pibs_t* pibs, wtap *wth, uint8_t *eth);
void process_file(pibs_t* pibs);
void pibs_dump_raw(pibs_t* pibs);
void pibs_dump_stats(pibs_t* pibs);
void process_redis_list(pibs_t* pibs);
#endif
