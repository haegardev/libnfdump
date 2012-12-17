/* This examples shows how libnfdump can be used to compute the port 
 * distribution for the protocol TCP.
 * An array is initialized with and the port numbers are used as index 
 * for this array. The port numbers are directly accessed in the flow record
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h> 

/* It is assumed that the directory libnfdump is somewhere in the library 
 * path such /usr/local/include/libnfdump/.
 * This directory should contain the files
 * - libnfdump.h
 * - nffile.h
 * In addition the libnfdump.so should be copied somewhere where the linker 
 * can find it (followed by an ldconfig invocation)
 */ 

#include <libnfdump/libnfdump.h>
#define TCP 6

int main (int argc, char* argv[])
{
    libnfstates_t* states;
    master_record_t* rec;
    int port_dist[0xFFFF]; /* Port distribution array */
    int i,numflows;

    
    
    bzero(&port_dist,sizeof(port_dist));

    if (argc != 2) {
        fprintf(stderr,"An nfcapd file needs to be passed as command line argument\n");
        return (EXIT_FAILURE);
    }
    
    /* Initialize libnfdump */
    states = initlib(NULL, argv[1],NULL);
    numflows = 0;
 
    if (states) {
        do {
            rec = get_next_record(states);
            if (rec) {
                /* Count only TCP ports */
                if (rec->prot == TCP){
                    /* Count the frequency of source ports */
                    port_dist[rec->srcport]++;
                    /* Count the frequency of destination ports */
                    port_dist[rec->dstport]++;
                    /* Count the number of flows */
                }
                numflows++;
            }
        } while (rec);
        
        /* Print the frequency of source ports */
        printf("Port Frequency\n");
        for (i=0; i<0xFFFF; i++) {
            printf("%8d %d\n",i,port_dist[i]); 
        } 
        printf("Processed flows: %d\n",numflows);

        /* Close the nfcapd file and free up internal states */
        libcleanup(states);
    }
    return(EXIT_SUCCESS);
} 
