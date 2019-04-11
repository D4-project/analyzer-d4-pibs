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
//TODO when attaching the next_item  must be recovered if results
//of previous runs need to be increased
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

void synseen_process_frame(pibs_t *pibs, wtap *wth, uint8_t* eth,
                           struct ip* ipv4, struct tcphdr* tcp)
{
    int_fast64_t lastseen;
    uint32_t ip;
    struct pcap_pkthdr pchdr;
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
        printf("%ld,%s,%d,%d\n",
               wth->rec.ts.secs, inet_ntoa(ipv4->ip_src), tcp->th_flags,
               ntohs(tcp->th_sport));
    }
    //TODO relative time
    //Purge old ips?
    if (pibs->should_writepcap) {
        pchdr.ts.tv_sec = wth->rec.ts.secs;
        //TODO other part of the timestamp
        pchdr.ts.tv_usec = wth->rec.ts.nsecs / 1000;
        pchdr.caplen =  wth->rec.rec_header.packet_header.caplen;
        pchdr.len =  wth->rec.rec_header.packet_header.len;
        pcap_dump((u_char*)pibs->dumper, &pchdr, eth);
    }
}

int synseen_init(pibs_t* pibs)
{
    pibs->data_size = sizeof(pibs_header_t) + NBINSCALE * NBINS * SZBIN * NBINITEMS * sizeof(item_t);
    pibs->data = calloc(pibs->data_size,1);
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
    return 1;
}
