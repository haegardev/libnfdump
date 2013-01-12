/*
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
 * This examples shows how libnfdump can be used to determine the evolution 
 * of a given port denoted iport. If a host belonging to a given AS number 
 * denoted targeted AS, and if this host interacts with an host x in another
 * AS on iport, then this interaction is recorded.   
 *
 * Example:
 * If you want to know how many hosts in your as connect to other hosts in 
 * other AS numbers on port 22, then tas = 0 and iport = 22.
 *
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

typedef union addr_s {
        uint32_t ipv4;
        uint64_t ipv6[2];
} addr_t;
    
/* Consumes 72 bytes instead of 256 */
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
} nfrecord_t;

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
    printf("sizeof(nfrecord_t) %d",sizeof(nfrecord_t));
    /* Initialize libnfdump */
    states = initlib(NULL, argv[1],NULL);
 
    if (states) {
        /* Open target file */
        fp = fopen("test.dat","w");
        if (!fp){
            fprintf(stderr,"Failed to open target file\n");
            goto out;
        }    
        do {
            r = get_next_record(states);
            if (r) {
                bzero(srec, sizeof(nfrecord_t));
                if ( (r->flags & FLAG_IPV6_ADDR ) != 0 ) {
                    /* Copy IPv6 source address */
                    srec->ipversion = 6;
                    srec->srcaddr.ipv6[0] = r->v6.srcaddr[0];
                    srec->srcaddr.ipv6[1] = r->v6.srcaddr[1];
                    /* Copy IPv6 destination address */
                    srec->dstaddr.ipv6[0] = r->v6.dstaddr[0];
                    srec->dstaddr.ipv6[1] = r->v6.dstaddr[1];
                }else{
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
                /* Save the structure in the file */
                i = fwrite(srec, sizeof(nfrecord_t),1, fp) != sizeof(nfrecord_t);
                if (i != 2) {
                    fprintf(stderr,"The outputfile is incomplete!\n");
                }
            }
        } while (r);
        fclose(fp);    
        out:
        /* Close the nfcapd file and free up internal states */
        libcleanup(states);
        //TODO free up memory
    }
    return(EXIT_SUCCESS);
} 
