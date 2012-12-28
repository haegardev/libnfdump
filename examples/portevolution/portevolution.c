/* This examples shows how libnfdump can be used to determine the evolution 
 * of a given port denoted iport. If a host belonging to a given AS number 
 * denoted targeted AS, and if this host interacts with an host x in another
 * AS on iport, then this interaction is recorded.   
 *
 * Example:
 * If you want to know how many hosts in your as connect to other hosts in 
 * other AS numbers on port 22, then tas = 0 and iport = 22.
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
  //FIXME does not take into account replies from the servers
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

void print_peer_scores(portevolution_t* pe, GSList* peers)
{
    GSList* item;
    peer_t* peer;
    item = peers;
    while (item) {
        if (item){
            peer = (peer_t*)item->data;
            //FIXME %d is not suited for uint_64
            printf("%d ",peer->appearance);                    
            item = item->next;
        }
    }
    printf("\n");
}

void print_source_list(portevolution_t* pe)
{
    GSList* item; 
    source_t* src;
    item = pe->srclist;
    char as[40];

    while (item != NULL){
        if (item){
            src = (source_t*)item->data;
            /* Compute the number of full peer lists */
            if (src->peermembers == MAXPEERS) {
                pe->fullpeerlists++;
            }
            src->ipv4addr = htonl(src->ipv4addr);
            inet_ntop(AF_INET, &src->ipv4addr, as, sizeof(as));
            printf("%s %d ", as,src->peermembers);
            print_peer_scores(pe, src->peers);
            item = item->next; 
        }
    }
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
            /* FIXME Check if the right fields are used? */
            /* FIXME change data type to uint64_t */
            peer->duration = r->last - r->first; 
            peer->packets = r->dPkts + r->out_pkts; 
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

int main (int argc, char* argv[])
{
    libnfstates_t* states;
    master_record_t* r;
    portevolution_t* pe; 
    if (argc != 2) {
        fprintf(stderr,"An nfcapd file needs to be passed as command line argument\n");
        return (EXIT_FAILURE);
    }
    /* Initialize libnfdump */
    states = initlib(NULL, argv[1],NULL);
    /* Initialize port evolution */
    pe = initevolution(25,0);
 
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
        printf("#Inspected port: %d\n",pe->iport);
        printf("#Source AS number: %d\n",pe->tas);
        printf("#Processed records: %d\n",pe->counter);
        printf("#Matched records: %d\n",pe->matched);
        printf("#Source list members: %d\n",pe->srcmembers);
        if (pe->srcmembers == MAXSOURCES){
            printf("#Warning: Source list is truncated\n");
        }      
        printf("#Number of missed peers: %d\n",pe->missedpeers);
        printf("#Number of full peer lists: %d\n", pe->fullpeerlists);
        printf("#Full peer list ratio: %.2f\n",
               (float) pe->fullpeerlists / (float) pe->srcmembers); 

        /* Close the nfcapd file and free up internal states */
        libcleanup(states);
        //TODO free up memory
    }
    return(EXIT_SUCCESS);
} 
