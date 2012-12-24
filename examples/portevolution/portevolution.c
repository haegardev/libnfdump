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

typedef struct source_s {
    GSList* peers;
    uint32_t ipv4addr;
    int members;
} source_t;

typedef struct peer_s {
    uint32_t ipv4addr;
    int score;
    //TODO extend this with other features such as volume, packets per second
    //etc
} peer_t;

//TODO pass iport as command line option
int iport = 25; /* Inspected port */
int tas   = 0;  /* Target AS */
int counter = 0; /* Number of processed flows */
int matched = 0; /* Number of matched flows */
GSList* srclist; /* List of IP addresses belonging to the AS denoted tas */


source_t* update_source_list(uint32_t ip);
GSList* update_peer_list(GSList* peerlist, uint32_t ip);

inline void process_record(master_record_t* r)
{
    source_t* src;
  //FIXME does not take into account replies from the servers
    /* Test if host from AS tas connects to port iport in other AS */
    if ((r->srcas == tas) && (r->dstport == iport)) {
        src = update_source_list(r->v4.srcaddr);
        if (src){
            src->peers=update_peer_list(src->peers,r->v4.dstaddr);
        }
        matched++;
    }
    counter++;
}


void init(void)
{
    srclist = NULL;

}

void print_peer_scores(GSList* peers)
{
    GSList* item;
    peer_t* peer;
    item = peers;
    while (item) {
        if (item){
            peer = (peer_t*)item->data;
            printf("%d ",peer->score);                    
            item = item->next;
        }
    }
    printf("\n");
}

void print_source_list(void)
{
    GSList* item; 
    source_t* src;
    item = srclist;
    char as[40];

    while (item != NULL){
        if (item){
            src = (source_t*)item->data;
            src->ipv4addr = htonl(src->ipv4addr);
            inet_ntop(AF_INET, &src->ipv4addr, as, sizeof(as));
            printf("%s %d ", as,src->members);
            print_peer_scores(src->peers);
            item = item->next; 
        }
    }
 }

GSList* search_address(uint32_t ip)
{
    GSList* item;
    item = srclist;
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

GSList* update_peer_list(GSList* peerlist, uint32_t ip)
{
    GSList* item;
    peer_t* peer;
    GSList* nplist;
    
    item = peerlist;
    nplist = peerlist;
    while (item) {
        if (item) {
            peer = (peer_t*) item->data;
            if (peer) {
                // existing peer found
                if (peer->ipv4addr == ip) {
                    peer->score++;
                    return item;
                }
            }
            item = item->next;
        }
    }
    /* The peer does not exists */
    //TODO check max number of peers
    peer = malloc(sizeof(peer_t));
    if (peer){
        peer->ipv4addr = ip; 
        peer->score = 1;
        nplist = g_slist_prepend(peerlist,peer);
   }
    /* If there is no memory no peer will be added */
    return nplist;
}



/* Update the source IP list and return a list of peers */
source_t* update_source_list(uint32_t ip)
{
    GSList *found;
    found = NULL;
    source_t* src;
    found = search_address(ip);
    if (found) {
        return (source_t*)found->data;
    }
    src = malloc(sizeof(source_t));
    if (src) {
        src->ipv4addr = ip;
        src->peers = NULL;
        src->members = 0;
        srclist = g_slist_prepend(srclist,src);
        return (source_t*)srclist->data;
    } else{
        fprintf(stderr,"Cannot allocate memory");
    }
    fprintf(stderr,"Something abnormal happend in update_source_list\n");
    return NULL;
}

int main (int argc, char* argv[])
{
    libnfstates_t* states;
    master_record_t* r;
    
    if (argc != 2) {
        fprintf(stderr,"An nfcapd file needs to be passed as command line argument\n");
        return (EXIT_FAILURE);
    }
    /* Initialize libnfdump */
    states = initlib(NULL, argv[1],NULL);
    init();
 
    if (states) {
        do {
            r = get_next_record(states);
            if (r) {
                /*FIXME currently cannot handle IPv6 */
                if ( (r->flags & FLAG_IPV6_ADDR ) != 0 ) {
                    continue;
                }
                process_record(r);
            }           
        } while (r);

        print_source_list();
        printf("#Inspected port: %d\n",iport);
        printf("#Source AS number: %d\n",tas);
        printf("#Processed records: %d\n",counter);
        printf("#Matched records: %d\n",matched);
        
        /* Close the nfcapd file and free up internal states */
        libcleanup(states);
        //TODO free up the used memory
    }
    return(EXIT_SUCCESS);
} 
