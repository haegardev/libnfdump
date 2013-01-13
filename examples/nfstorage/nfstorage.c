/*
 *   Example to reduce the the storage of netflow records
 * 
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU Affero General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU Affero General Public License for more details.
 *
 *   You should have received a copy of the GNU Affero General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The generated file can then be compressed with gzip or zlib
 */ 
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h> 
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <glib.h>
#include <string.h>
#include <libnfdump/libnfdump.h>
#include <assert.h>

/* Attributes related to one instance of nfstorage */
typedef struct nfstorage_s {
    /* IP address directory size */
    uint32_t dir_size;
    uint32_t max_dir_size;
    GSList* addrlst;
} nfstorage_t;

typedef union addr_s {
        uint32_t ipv4;
        uint64_t ipv6[2];
} addr_t;

/* Directory of currently used nfrecord_t buffers */
typedef union addr_dir_s {
    addr_t addr;
    uint32_t n_flows; 
    /* n_flows is the number of flows in the buffer and is used to determine
     * if the buffer is full and needs to be swapped
     */
    uint64_t last_cnt; /* Last value of the flow counter */
    /* Each flow record correspond to a number. Each time a flow is put is
     * put in the buffer the value of the counter is also saved. Hence,
     * the swap routine is able to determine buffers that were not updated
     * for a long time
     */
} addr_dir_t;

/* Consumes 128 bytes instead of 256 */
typedef struct nfrecord_s{
    uint8_t  ipversion;
    addr_t srcaddr;
    addr_t dstaddr;
    uint16_t srcport;
    uint16_t dstport;
    uint16_t msec_first;
    uint16_t msec_last;
    uint32_t first;
    uint32_t last;
    uint8_t prot; 
    uint64_t dPkts;
    uint64_t dOctets;
    uint32_t srcas;
    uint32_t dstas;
    uint64_t out_pkts;
    uint64_t out_bytes;
    /* align structure to better fill page tables *
     * These bytes could be filles with something more useful such as flow 
     * duration etc
     */
    uint8_t padding[32];
} nfrecord_t;

void create_addr_directory(nfstorage_t* nfs, uint32_t maxsize) {
    nfs->dir_size = 0;
    nfs->max_dir_size = maxsize;
    nfs->addrlst = NULL; 
}

void copy_fields(nfrecord_t* srec, master_record_t* r)
{
    assert(srec && r);    
   
    if ( (r->flags & FLAG_IPV6_ADDR ) != 0 ) {
        /* Copy IPv6 source address */
        srec->ipversion = 6;
        srec->srcaddr.ipv6[0] = r->v6.srcaddr[0];
        srec->srcaddr.ipv6[1] = r->v6.srcaddr[1];
        /* Copy IPv6 destination address */
        srec->dstaddr.ipv6[0] = r->v6.dstaddr[0];
        srec->dstaddr.ipv6[1] = r->v6.dstaddr[1];
    } else {
        /* Copy IPv4 source address */
        srec->srcaddr.ipv4 = r->v4.srcaddr;
        srec->dstaddr.ipv4 = r->v4.dstaddr;
    }
    /* Copy source port */
    srec->srcport = r->srcport;
    /* Copy destination port */
    srec->dstport = r->dstport;
    /* Copy time stamp information */
    srec->msec_first = r->msec_first;
    srec->msec_last = r->msec_last;  
    /* Copy protocol */          
    srec->prot = r->prot;
    /* Copy packets and Octects */
    srec->dPkts = r->dPkts;
    srec->dOctets = r->dOctets;
    srec->out_pkts = r->out_pkts;
    srec->out_bytes = r->out_bytes;
    /* Copy AS information */
    srec->srcas = r->srcas;
    srec->dstas = r->dstas;
}  


int main (int argc, char* argv[])
{
    FILE* fp;
    int i;
    libnfstates_t* states;
    master_record_t* r;
    nfrecord_t* srec;
    if (argc != 2) {
        fprintf(stderr,"An nfcapd file needs to be passed as command line argument\n");
        return (EXIT_FAILURE);
    }
    /* Initilize stripped IP record */
    srec = calloc(sizeof(nfrecord_t),1);
    if (!srec) {
        fprintf(stderr, "No memory\n");
        return EXIT_FAILURE;
    }
    printf("sizeof(nfrecord_t) %d\n",sizeof(nfrecord_t));
    /* Initialize libnfdump */
    states = initlib(NULL, argv[1],NULL);
 
    if (states) {
        /* Open target file */
        fp = fopen("test.dat","w");
        if (!fp){
            fprintf(stderr,"Failed to open target file\n");
            goto out;
        }
        printf("Opened test.dat ..\n");    
        do {
            r = get_next_record(states);
            if (r) {
                bzero(srec, sizeof(nfrecord_t));
                copy_fields(srec, r);
                /* Save the structure in the file */
                i = fwrite(srec, sizeof(nfrecord_t),1, fp) != sizeof(nfrecord_t);
                if (i != 1) {
                    fprintf(stderr,"The outputfile is incomplete!\n");
                }
           }
        } while (r);
        fclose(fp);    
        printf("Storage done. You could compress the file test.dat with gzip or zlib.\n");
        out:
        /* Close the nfcapd file and free up internal states */
        free(srec);
        libcleanup(states);
    }
    return(EXIT_SUCCESS);
} 
