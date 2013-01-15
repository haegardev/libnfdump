/*
 *   Evolution of the usage of a port in another AS  from an nfcapd file
 *   Copyright (C) 2012  Gerard Wagener
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
 * This examples shows how libnfdump can be used to determine the evolution 
 * of a given port denoted iport. If a host belonging to a given AS number 
 * denoted targeted AS, and if this host interacts with an host x in another
 * AS on iport, then this interaction is recorded.   
 *
 * Example:
 * If you want to know how many hosts in your as connect to other hosts in 
 * other AS numbers on port 22, then tas = 0 and iport = 22.
 *
 * TODO add support to handle more sourcelist such that more than 1 protocol 
 * canbe analyzed at the same time.
 * TODO export other fields aswell input, output
 * TODO Put these functions in a library
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
#include <getopt.h>

#include <libnfdump/libnfdump.h>
#define TCP 6
#define MAXPEERS 4096 
#define MAXSOURCES 4096 

typedef struct source_s {
    GSList* peers;
    uint32_t ipv4addr;
    int peermembers;
} source_t;

typedef struct peer_s {
    uint32_t ipv4addr;
    uint64_t appearance; /* Parameter how many times the given IP appeared */
    uint64_t duration; /* The total amount of durations */
    uint64_t packets; /* The total amount of packets */
    uint64_t input;
    uint64_t output;
    uint64_t dPkts;
    uint64_t dOctets;
    uint64_t out_pkts;
    uint64_t out_bytes;
    /* Put here your other features that should be recorded */
} peer_t;

typedef struct portevolution_s{
    int iport; /* Inspected port */
    int tas;  /* Target AS */
    int counter; /* Number of processed flows */
    int matched; /* Number of matched flows */
    GSList* srclist; /* List of IP addresses belonging to the AS denoted tas */
    int srcmembers;
    int missedpeers; /* Number of missed peers */
    int fullpeerlists; /* Number of full peer lists */
} portevolution_t;

//TODO set errno or something like that in the portevolution_t
/* Functions */
portevolution_t* initevolution(int iport, int tas);
int process_record(portevolution_t* pe, master_record_t* r);
void print_peer_scores(portevolution_t* pe, GSList* peers);
void print_source_list(portevolution_t* pe);
GSList* search_address(portevolution_t* pe, uint32_t ip);
GSList* update_peer_list(portevolution_t* pe, source_t* src, master_record_t* r);
source_t* update_source_list(portevolution_t* pe, uint32_t ip);

int process_record(portevolution_t* pe, master_record_t* r)
{
    source_t* src;
    /* Test if host from AS tas connects to port iport in other AS */
    if ((r->srcas == pe->tas) && (r->dstport == pe->iport)) {
        src = update_source_list(pe, r->v4.srcaddr);
        if (src){
            src->peers=update_peer_list(pe, src,r);
        }else{
            /* The source list is full tell process_record to stop */
            return 0;    
        }
        pe->matched++;
    }
    pe->counter++;
    /* It is assumed that everything went fine for this record */
    return 1;
}


portevolution_t* initevolution(int iport, int tas)
{
    portevolution_t* pe;
    pe = malloc(sizeof(portevolution_t));
    if (pe){ 
        pe->srclist = NULL;
        pe->iport = iport; 
        pe->tas   = tas;  
        pe->counter = 0;
        pe->matched = 0;
        pe->srclist = NULL; 
        pe->srcmembers = 0; 
        pe->missedpeers = 0;
        pe->fullpeerlists = 0;
    }
    return pe;
}

void print_peer_packets(portevolution_t* pe, GSList* peers)
{
    GSList* item;
    peer_t* peer;
    item = peers;
    printf("{\"packets\":[");
    while (item) {
        if (item){
            peer = (peer_t*)item->data;
            printf("%lu",peer->appearance);                    
            if (item->next)
                printf(",");
            item = item->next;
        }
    }
    printf("]},"); /* Close the packet sequence */
}

void print_peer_durations(portevolution_t* pe, GSList* peers)
{
    GSList* item;
    peer_t* peer;
    item = peers;
    printf("{\"durations\":[");
    while (item) {
        if (item){
            peer = (peer_t*)item->data;
            printf("%lu",peer->duration);                    
            if (item->next)
                printf(",");
            item = item->next;
        }
    }
    printf("]},"); /* Close the durations sequence */
}

void print_peer_input(portevolution_t* pe, GSList* peers)
{
    GSList* item;
    peer_t* peer;
    item = peers;
    printf("{\"input\":[");
    while (item) {
        if (item){
            peer = (peer_t*)item->data;
            printf("%lu",peer->input);                    
            if (item->next)
                printf(",");
            item = item->next;
        }
    }
    printf("]},"); /* Close the input sequence */
}

void print_peer_output(portevolution_t* pe, GSList* peers)
{
    GSList* item;
    peer_t* peer;
    item = peers;
    printf("{\"output\":[");
    while (item) {
        if (item){
            peer = (peer_t*)item->data;
            printf("%lu",peer->output);                    
            if (item->next)
                printf(",");
            item = item->next;
        }
    }
    printf("]},"); /* Close the output sequence */
}

void print_peer_dPkts(portevolution_t* pe, GSList* peers)
{
    GSList* item;
    peer_t* peer;
    item = peers;
    printf("{\"dPkts\":[");
    while (item) {
        if (item){
            peer = (peer_t*)item->data;
            printf("%lu",peer->dPkts);                    
            if (item->next)
                printf(",");
            item = item->next;
        }
    }
    printf("]},"); /* Close the dPkts sequence */
}

void print_peer_dOctets(portevolution_t* pe, GSList* peers)
{
    GSList* item;
    peer_t* peer;
    item = peers;
    printf("{\"dOctets\":[");
    while (item) {
        if (item){
            peer = (peer_t*)item->data;
            printf("%lu",peer->dOctets);                    
            if (item->next)
                printf(",");
            item = item->next;
        }
    }
    printf("]},"); /* Close the dPkts sequence */
}

void print_peer_out_pkts(portevolution_t* pe, GSList* peers)
{
    GSList* item;
    peer_t* peer;
    item = peers;
    printf("{\"out_pkts\":[");
    while (item) {
        if (item){
            peer = (peer_t*)item->data;
            printf("%lu",peer->out_pkts);                    
            if (item->next)
                printf(",");
            item = item->next;
        }
    }
    printf("]}"); /* Close the dPkts sequence */
}

void print_peer_scores(portevolution_t* pe, GSList* peers)
{
    print_peer_packets(pe,peers);
    print_peer_durations(pe,peers);
    print_peer_input(pe,peers);
    print_peer_output(pe,peers);
    print_peer_dPkts(pe,peers);
    print_peer_dOctets(pe,peers);
    print_peer_out_pkts(pe,peers);
    printf("]}");
}

void print_source_list(portevolution_t* pe)
{
    GSList* item; 
    source_t* src;
    item = pe->srclist;
    char as[40];
    printf("[{\"data\":[");
    while (item != NULL){
        if (item){
            src = (source_t*)item->data;
            /* Compute the number of full peer lists */
            if (src->peermembers == MAXPEERS) {
                pe->fullpeerlists++;
            }
            src->ipv4addr = htonl(src->ipv4addr);
            inet_ntop(AF_INET, &src->ipv4addr, as, sizeof(as));
            printf("{\"%s\":[{\"num_peers\":%d},", as,src->peermembers);
            print_peer_scores(pe, src->peers);
            if (item->next)
                printf(",\n");
            item = item->next; 
        }
    }
    printf("]},");
 }

GSList* search_address(portevolution_t* pe, uint32_t ip)
{
    GSList* item;
    item = pe->srclist;
    source_t *src;
    while (item) {
        if (item){
            src = (source_t*)item->data;
            if (src->ipv4addr == ip){
                return item;
            }
        item = item->next; 
        }    
    }
    return NULL; 
}

GSList* update_peer_list(portevolution_t* pe, source_t* src, master_record_t* r)
{
    GSList* item;
    peer_t* peer;
    GSList* nplist;
    GSList* peerlist;
    peerlist = src->peers;
    item = peerlist;
    nplist = peerlist;
    while (item) {
        if (item) {
            peer = (peer_t*) item->data;
            if (peer) {
                // existing peer found
                if (peer->ipv4addr == r->v4.dstaddr) {
                    peer->appearance++;
                    peer->duration+=(r->last - r->first);
                    peer->packets+=r->dPkts + r->out_pkts;
                    peer->input+=r->input;
                    peer->output+=r->output;
                    peer->dPkts+= r->dPkts;
                    peer->dOctets+= r->dOctets;
                    peer->out_pkts+= r->out_pkts;
                    peer->out_bytes+= r->out_bytes;
            nplist = g_slist_prepend(peerlist,peer);
                    return peerlist;
                }
            }
            item = item->next;
        }
    }
    /* The peer does not exists */
    if (src->peermembers < MAXPEERS) {
        peer = malloc(sizeof(peer_t));
        if (peer) {
            peer->ipv4addr = r->v4.dstaddr; 
            peer->appearance = 1;
            peer->duration = r->last - r->first; 
            peer->packets = r->dPkts + r->out_pkts;
            peer->input = r->input;
            peer->output = r->output;
            peer->dPkts  = r->dPkts;
            peer->dOctets = r->dOctets;
            peer->out_pkts = r->out_pkts;
            peer->out_bytes = r->out_bytes;
            nplist = g_slist_prepend(peerlist,peer);
            src->peermembers++;
        }
    } else {
        pe->missedpeers++;
    } 
    /* If there is no memory or the peer list full no peer will be added 
     * and the old lits is returned 
     */
    return nplist;
}



/* Update the source IP list and return a list of peers */
source_t* update_source_list(portevolution_t* pe, uint32_t ip)
{
    GSList *found;
    found = NULL;
    source_t* src;
    found = search_address(pe, ip);
    if (found) {
        return (source_t*)found->data;
    }
    src = malloc(sizeof(source_t));
    if (src) {
        if (pe->srcmembers < MAXSOURCES) {
            src->ipv4addr = ip;
            src->peers = NULL;
            src->peermembers = 0;
            pe->srclist = g_slist_prepend(pe->srclist,src);
            pe->srcmembers++;
            return (source_t*)(pe->srclist)->data;
        }
    } else{
        fprintf(stderr,"Cannot allocate memory");
    }
    /* Something abnormal happend return an error */
    return NULL;
}

int process_nfcapd_file(char* nffile, char* resfile, uint16_t port, uint16_t as)
{

    libnfstates_t* states;
    master_record_t* r;
    portevolution_t* pe; 

    /* Either nffilename or jsfilename was not specified */
    if (!(nffile && resfile))
        return EXIT_FAILURE;

    /* Initialize libnfdump */
    states = initlib(NULL, nffile, NULL);
    /* Initialize port evolution */
    pe = initevolution(port,as);
 
    if (states) {
        do {
            r = get_next_record(states);
            if (r) {
                /*FIXME currently cannot handle IPv6 */
                if ( (r->flags & FLAG_IPV6_ADDR ) != 0 ) {
                    continue;
                }
                if (!process_record(pe, r)) {
                    break;
                }
            }           
        } while (r);

        print_source_list(pe);
        /* Export metadata about processing aswell */
        printf("{\"Inspected Port\":%d},",pe->iport);
        printf("{\"Source ASN\":%d},",pe->tas);
        printf("{\"Processed Records\":%d},",pe->counter);
        printf("{\"Matched Records\":%d},",pe->matched);
        printf("{\"Source List Members\":%d},",pe->srcmembers);
        if (pe->srcmembers == MAXSOURCES){
            printf("{\"Truncated Source List\":true},");
        } else { 
            printf("{\"Truncated Source List\":false},");
        }
        printf("{\"Number of missed peers\":%d},",pe->missedpeers);
        printf("{\"Number of full peer lists\":%d},", pe->fullpeerlists);
        printf("{\"Full peer list ratio\":%.2f}",
               (float) pe->fullpeerlists / (float) pe->srcmembers); 

        printf("]\n");
        /* Close the nfcapd file and free up internal states */
        libcleanup(states);
        //TODO free up memory
    }
    return(EXIT_SUCCESS);
}

void usage (void)
{
    printf("%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n", 
"Usage portevolution [-h] [-a X -p P -w]  ", 
"Do some accounting from all the hosts belong to an AS X that connect to AS Y",
"on port P.",
"\nOPTIONS\n"
"   -h --help   shows this screen\n"
"   -a --as     specify the source AS number",
"   -p --port   sepcify the destination port on a host in another AS",
"   -w --write  specify the target file where the results are written",
"   -r --read   specify an nfcapd file that is read by this program",
"\nAUTHOR",
"   Gerard Wagener (2013)",
"\nLICENSE",
"   GNU Affero General Public License");
}

int main (int argc, char* argv[])
{
    int next_option = 0;
    const char* const short_options = "ha:p:w:r:";
    const struct option long_options[] = {
                { "help", 0, NULL, 'h' },
                { "as", 1, NULL, 'a' },
                { "port", 1, NULL, 'p' },
                { "write", 1, NULL, 'w'},
                { "read",1, NULL, 'r'},
                {NULL,0,NULL,0}};
    char* nffile = NULL;
    char* resfile = NULL;
    uint16_t as = 0;
    uint32_t port = 0;     

    do {
        next_option = getopt_long (argc, argv, short_options, 
                                   long_options, NULL);
        if (next_option > 0) {
            switch(next_option)
            {
            case 'h':
                usage();
                return EXIT_SUCCESS;
            case 'a':
                as = atoi(optarg);
                break;
            case 'p':
                port = atoi(optarg);
                break;
            case 'w':
                resfile = optarg;
                break;
            case 'r':
                nffile = optarg;
                break; 
            default:
                /* Something unexpected happended */
                return EXIT_FAILURE;
            }
        }
    } while(next_option != -1);

    /* Check parameters */
    if (!port) {
        fprintf(stderr,"A port number must be specified\n");
        return EXIT_FAILURE;
    }
    
    if (!nffile) {
        fprintf(stderr,"An nfcapd filename must be specified\n");
        return EXIT_FAILURE;
    }

    if (!resfile) {
        fprintf(stderr,"A result filename must be specified\n");
        return EXIT_FAILURE;
    }
    
    process_nfcapd_file(nffile, resfile, port, as);
        
    return EXIT_SUCCESS;
} 
