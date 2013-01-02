/*
 *  Copyright (c) 2012, Gerard Wagener
 *  Copyright (c) 2009, Peter Haag
 *  Copyright (c) 2004-2008, SWITCH - Teleinformatikdienste fuer Lehre und Forschung
 *  All rights reserved.
 *  
 *  Redistribution and use in source and binary forms, with or without 
 *  modification, are permitted provided that the following conditions are met:
 *  
 *   * Redistributions of source code must retain the above copyright notice, 
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright notice, 
 *     this list of conditions and the following disclaimer in the documentation 
 *     and/or other materials provided with the distribution.
 *   * Neither the name of SWITCH nor the names of its contributors may be 
 *     used to endorse or promote products derived from this software without 
 *     specific prior written permission.
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE 
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
 *  POSSIBILITY OF SUCH DAMAGE.
 *  
 */

/* 
 * libnfreader can be compiled as shared library with the purpose to access
 * the nfcapd datastructures directly without using Input/Output. Hence, 
 * netflow records can be directly accessed from other programs implemented
 * in C or in other languages such as python.
 *
 * How to build libnfreader
 * 
 * export CFLAGS=-fPIC and build nfdump using standard methods such as
 * ./configure
 * make 
 *
 * gcc -fPIC -c libnfreader.c -I ../ -ggdb
 * gcc -shared -Wl,-soname,libnfreader.so -o libnfreader.so  nfreader.o \  
 * nffile.o flist.o util.o minilzo.o nfx.o -lc
 *
 */
 
#include "config.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "nffile.h"
#include "nfx.h"
#include "util.h"
#include "flist.h"
#include "libnfdump.h"
#define BUFFSIZE 1048576
#define MAX_BUFFER_SIZE 104857600

#if ( SIZEOF_VOID_P == 8 )
typedef uint64_t    pointer_addr_t;
#else
typedef uint32_t    pointer_addr_t;
#endif

// module limited globals
extension_map_list_t extension_map_list;

/* Function Prototypes */
static int try_next_block(libnfstates_t* states);

/* Exported functions of the library*/
void print_record(void *record);
libnfstates_t* initlib(char* Mdirs, char* rfile, char* Rfile);
void libcleanup(libnfstates_t* states);
master_record_t* get_next_record(libnfstates_t* states);

/* Functions */

#include "nffile_inline.c"


void print_record(void *record) {
char 		as[40], ds[40], datestr1[64], datestr2[64];
time_t		when;
struct tm 	*ts;
master_record_t *r = (master_record_t *)record;

	if ( (r->flags & FLAG_IPV6_ADDR ) != 0 ) { // IPv6
		r->v6.srcaddr[0] = htonll(r->v6.srcaddr[0]);
		r->v6.srcaddr[1] = htonll(r->v6.srcaddr[1]);
		r->v6.dstaddr[0] = htonll(r->v6.dstaddr[0]);
		r->v6.dstaddr[1] = htonll(r->v6.dstaddr[1]);
		inet_ntop(AF_INET6, r->v6.srcaddr, as, sizeof(as));
		inet_ntop(AF_INET6, r->v6.dstaddr, ds, sizeof(ds));
	} else {	// IPv4
		r->v4.srcaddr = htonl(r->v4.srcaddr);
		r->v4.dstaddr = htonl(r->v4.dstaddr);
		inet_ntop(AF_INET, &r->v4.srcaddr, as, sizeof(as));
		inet_ntop(AF_INET, &r->v4.dstaddr, ds, sizeof(ds));
	}
	as[40-1] = 0;
	ds[40-1] = 0;

	when = r->first;
	ts = localtime(&when);
	strftime(datestr1, 63, "%Y-%m-%d %H:%M:%S", ts);

	when = r->last;
	ts = localtime(&when);
	strftime(datestr2, 63, "%Y-%m-%d %H:%M:%S", ts);

	printf( "\n"
"Flow Record: \n"
"  srcaddr     = %16s\n"
"  dstaddr     = %16s\n"
"  first       =       %10u [%s]\n"
"  last        =       %10u [%s]\n"
"  msec_first  =            %5u\n"
"  msec_last   =            %5u\n"
"  prot        =              %3u\n"
"  srcport     =            %5u\n"
"  dstport     =            %5u\n"
"  dPkts       =       %10llu\n"
"  dOctets     =       %10llu\n"
, 
		as, ds, r->first, datestr1, r->last, datestr2, r->msec_first, r->msec_last, 
		r->prot, r->srcport, r->dstport,
		(unsigned long long)r->dPkts, (unsigned long long)r->dOctets);


} // End of print_record


libnfstates_t* initlib(char* Mdirs, char* rfile, char* Rfile)
{
	libnfstates_t *states;
    states = malloc(sizeof(libnfstates_t));
    if (!states) {
        perror("Memory allocation error");
        return NULL;
    }

    /* Initialize the structure */
    bzero(states, sizeof(libnfstates_t));

    #ifdef COMPAT15
    states->v1_map_done = 0;
    #endif

    InitExtensionMaps(&extension_map_list);
   	SetupInputFileSequence(Mdirs, rfile, Rfile);

    InitFileCnt(); 
	states->rfd = GetNextFile(0, 0, 0, NULL);
	if ( states->rfd < 0 ) {
		if ( states->rfd == FILE_ERROR )
			perror("Can't open input file for reading");
		return NULL;
	}

	// allocate buffer suitable for netflow version
	states->buffer_size = BUFFSIZE;
	states->in_buff = (common_record_t *) malloc(states->buffer_size);

	if ( !states->in_buff ) {
		perror("Memory allocation error");
		close(states->rfd);
		return NULL;
	}

	states->done = 0;
	states->inblock = 0;
	states->records_present = 0;
    return states;
}


void libcleanup(libnfstates_t* states)
{ 
	if ( states->rfd > 0 ) 
		close(states->rfd);

	free((void *)states->in_buff);

	PackExtensionMapList(&extension_map_list);
}



// Returns 0 if there are more records
// Returns 1 if there are no records
// The master record is returned via argument
static int try_next_block(libnfstates_t* states) {
	/* By default no blocks are assumed */
	states->records_present = 0;
	// Get the first file handle
	if ( !states->done ) {
		if (!states->inblock){
		// get next data block from file
		states->ret = ReadBlock(states->rfd, &(states->block_header), (void *)states->in_buff, &(states->string));

		switch (states->ret) {
			case NF_CORRUPT:
			case NF_ERROR:
				if ( states->ret == NF_CORRUPT )
					fprintf(stderr, "Skip corrupt data file '%s': '%s'\n",GetCurrentFilename(), states->string);
				else 
					fprintf(stderr, "Read error in file '%s': %s\n",GetCurrentFilename(), strerror(errno) );
				// fall through - get next file in chain
			case NF_EOF:
				states->rfd = GetNextFile(states->rfd, 0, 0, NULL);
				if ( states->rfd < 0 ) {
					if ( states->rfd == NF_ERROR )
						fprintf(stderr, "Read error in file '%s': %s\n",GetCurrentFilename(), strerror(errno) );

					// rfd == EMPTY_LIST
					states->done = 1;
				} // else continue with next file
				return 0;	
		}

#ifdef COMPAT15
		if ( states->block_header.id == DATA_BLOCK_TYPE_1 ) {
			common_record_v1_t *v1_record = (common_record_v1_t *)states->in_buff;
			// create an extension map for v1 blocks
			if ( states->v1_map_done == 0 ) {
				extension_map_t *map = malloc(sizeof(extension_map_t) + 2 * sizeof(uint16_t) );
				if ( ! map ) {
					perror("Memory allocation error");
					exit(255);
				}
				map->type 	= ExtensionMapType;
				map->size 	= sizeof(extension_map_t) + 2 * sizeof(uint16_t);
				map->map_id = 0;
				map->ex_id[0]  = EX_IO_SNMP_2;
				map->ex_id[1]  = EX_AS_2;
				map->ex_id[2]  = 0;

				Insert_Extension_Map(&extension_map_list, map);

				states->v1_map_done = 1;
			}

			// convert the records to v2
			for ( states->i=0; states->i < states->block_header.NumRecords; states->i++ ) {
				common_record_t *v2_record = (common_record_t *)v1_record;
				Convert_v1_to_v2((void *)v1_record);
				// now we have a v2 record -> use size of v2_record->size
				v1_record = (common_record_v1_t *)((pointer_addr_t)v1_record + v2_record->size);
			}
			states->block_header.id = DATA_BLOCK_TYPE_2;
		}
#endif

		if ( states->block_header.id != DATA_BLOCK_TYPE_2 ) {
			fprintf(stderr, "Can't process block type %u. Skip block.\n", states->block_header.id);
			return 0;
		}

		states->flow_record = states->in_buff;
		states->inblock =1;
		states->i = 0;
		} // End if not inblock 


		if (states->inblock){
			if ( states->i < states->block_header.NumRecords){  

			if ( states->flow_record->type == CommonRecordType ) {
				uint32_t map_id = states->flow_record->ext_map;
				if ( extension_map_list.slot[map_id] == NULL ) {
					fprintf(stderr, "Corrupt data file! No such extension map id: %u. Skip record", states->flow_record->ext_map );
				} else {
					ExpandRecord_v2( states->flow_record, extension_map_list.slot[states->flow_record->ext_map], &(states->master_record));

					// update number of flows matching a given map
					extension_map_list.slot[map_id]->ref_count++;
			
					states->records_present = 1;

				}

			} else if ( states->flow_record->type == ExtensionMapType ) {
				extension_map_t *map = (extension_map_t *)states->flow_record;

				if ( Insert_Extension_Map(&extension_map_list, map) ) {
					 // flush new map
				} // else map already known and flushed

			} else {
				fprintf(stderr, "Skip unknown record type %i\n", states->flow_record->type);
			}

			// Advance pointer by number of bytes for netflow record
			states->flow_record = (common_record_t *)((pointer_addr_t)states->flow_record + states->flow_record->size);	
			states->i++; /* Increase the record counter */
			}else{
			//The block has been processed, it's time to get a new one
				states->inblock = 0;
			}
		} // end in block 

	} //End if done
	return states->done; 
} // End of process_data


master_record_t* get_next_record(libnfstates_t* states)
{
	//Go though the stream until a record is found
	do {
		if (states->done){
			return NULL;
		}
		try_next_block(states);
		
	}while(!states->records_present);
	return &(states->master_record);
}
