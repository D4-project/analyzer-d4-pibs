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
    //TODO error handling
    //TODO check if size is correct
    pibs->filename = calloc(FILENAME_MAX,1);
    pibs->uuid = calloc(SZUUID,1);
    pibs->key = calloc(SZKEY,1);
    pibs->server = calloc(SZSERVER,1);
    // Initialize the various processors
    synseen_init(pibs);
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
