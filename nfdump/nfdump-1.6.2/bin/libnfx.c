/*
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
 *  $Author: haag $
 *
 *  $Id: nfx.c 58 2010-02-26 12:26:07Z haag $
 *
 *  $LastChangedRevision: 58 $
 *	
 */

#include "config.h"

#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <syslog.h>
#include <stdarg.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#ifndef DEVEL
#   define dbg_printf(...) /* printf(__VA_ARGS__) */
#else
#   define dbg_printf(...) printf(__VA_ARGS__)
#endif

#include "nf_common.h"
#include "nffile.h"
#include "nfx.h"

/* global vars */

/*
 * see nffile.h for detailed extension description
 */
extension_descriptor_t extension_descriptor[] = {
	// fill indices 0 - 3
	{ COMMON_BLOCK_ID,		0,	 0, 1,   "Required extension: Common record"},
	{ EX_IPv4v6,			0,	 0, 1,   "Required extension: IPv4/IPv6 src/dst address"},
	{ EX_PACKET_4_8,		0,	 0, 1,   "Required extension: 4/8 byte input packets"},
	{ EX_BYTE_4_8,			0,	 0, 1,   "Required extension: 4/8 byte input bytes"},

	// the optional extension
	{ EX_IO_SNMP_2, 		4, 	 1, 1,   "2 byte input/output interface index"},
	{ EX_IO_SNMP_4, 		8, 	 1, 1,   "4 byte input/output interface index"},
	{ EX_AS_2, 				4, 	 2, 1,   "2 byte src/dst AS number"},
	{ EX_AS_4, 				8, 	 2, 1,   "4 byte src/dst AS number"},
	{ EX_MULIPLE, 			4, 	 3, 0,   "dst tos, direction, src/dst mask"}, 
	{ EX_NEXT_HOP_v4,		4,	 4, 0,   "IPv4 next hop"},
	{ EX_NEXT_HOP_v6,		16,	 4, 0,   "IPv6 next hop"},
	{ EX_NEXT_HOP_BGP_v4,	4,	 5, 0,   "IPv4 BGP next IP"},
	{ EX_NEXT_HOP_BGP_v6,	16,	 5, 0,   "IPv6 BGP next IP"},
	{ EX_VLAN,				4,	 6, 0,   "src/dst vlan id"},
	{ EX_OUT_PKG_4,			4,	 7, 0,   "4 byte output packets"},
	{ EX_OUT_PKG_8,			8,	 7, 0,   "8 byte output packets"},
	{ EX_OUT_BYTES_4,		4,	 8, 0,   "4 byte output bytes"},
	{ EX_OUT_BYTES_8,		8,	 8, 0,   "8 byte output bytes"},
	{ EX_AGGR_FLOWS_4,		4,	 9, 0,   "4 byte aggregated flows"},
	{ EX_AGGR_FLOWS_8,		8,	 9, 0,   "8 byte aggregated flows"},
	{ EX_MAC_1,				16,	10, 0,   "in src/out dst mac address"},
	{ EX_MAC_2,				16,	11, 0,   "in dst/out src mac address"},
	{ EX_MPLS,				40,	12, 0,   "MPLS Labels"},
	{ EX_ROUTER_IP_v4,		4,	13, 0,   "IPv4 router IP addr"},
	{ EX_ROUTER_IP_v6,		16,	13, 0,   "IPv6 router IP addr"},
	{ EX_ROUTER_ID,			4,	14, 0,   "router ID"},

	// last entry
	{ 0,	0,	0, 0,	NULL }
};

uint32_t Max_num_extensions;

void InitExtensionMaps(extension_map_list_t *extension_map_list ) {
	memset((void *)extension_map_list->slot, 0, MAX_EXTENSION_MAPS * sizeof(extension_info_t *));
	memset((void *)extension_map_list->page, 0, MAX_EXTENSION_MAPS * sizeof(extension_info_t *));

	extension_map_list->next_free = 0;
	extension_map_list->max_used  = -1;

} // End of InitExtensionMaps

void FreeExtensionMaps(extension_map_list_t *extension_map_list) {
int	i;

	if ( extension_map_list == NULL ) 
		return;
	
	// free all maps
	for ( i=0; i <= extension_map_list->max_used; i++ ) {
		if ( extension_map_list->slot[i] ) {
			if ( extension_map_list->slot[i]->map ) {
				free(extension_map_list->slot[i]->map);
				extension_map_list->slot[i]->map = NULL;
			}
			free(extension_map_list->slot[i]);
			extension_map_list->slot[i] = NULL;
		}
		
	}

	// free all paged maps
	for ( i=0; i < extension_map_list->next_free; i++ ) {
		if ( extension_map_list->page[i] ) {
			if ( extension_map_list->page[i]->map ) {
				free(extension_map_list->page[i]->map);
				extension_map_list->page[i]->map = NULL;
			}
			free(extension_map_list->page[i]);
			extension_map_list->page[i] = NULL;
		}
	}

	InitExtensionMaps(extension_map_list);

} // End of FreeExtensionMaps

int Insert_Extension_Map(extension_map_list_t *extension_map_list, extension_map_t *map) {
uint32_t next_free = extension_map_list->next_free;
uint16_t map_id;

	map_id = map->map_id == INIT_ID ? 0 : map->map_id & EXTENSION_MAP_MASK;
	map->map_id = map_id;
	dbg_printf("Insert Extension Map:\n");
#ifdef DEVEL
	PrintExtensionMap(map);
#endif
	// is this slot free
	if ( extension_map_list->slot[map_id] ) {
		int i, map_found;
		dbg_printf("Map %d already exists\n", map_id);
		// no - check if same map already in slot
		if ( extension_map_list->slot[map_id]->map->size == map->size ) {
			// existing map and new map have the same size 
			dbg_printf("New map same size:\n");

			// we must compare the maps
			i = 0;
			while ( extension_map_list->slot[map_id]->map->ex_id[i] && (extension_map_list->slot[map_id]->map->ex_id[i] == map->ex_id[i]) ) 
				i++;

			// if last entry == 0 => last map entry => maps are the same
			if ( extension_map_list->slot[map_id]->map->ex_id[i] == 0 ) {
				dbg_printf("Same map => nothing to do\n");
				// same map
				return 0;
			} 
			dbg_printf("Different map => continue\n");
		}

		dbg_printf("Search for map in extension page\n");
		map_found = -1;
		// new map is different but has same id - search for map in page list
		for ( i = 0 ; i < next_free; i++ ) {
			int j;
			j = 0;
			if ( extension_map_list->page[i]->map->size == map->size ) {
				while ( extension_map_list->page[i]->map->ex_id[j] && (extension_map_list->page[i]->map->ex_id[j] == map->ex_id[j]) ) 
					j++;
			}
			if ( extension_map_list->page[i]->map->ex_id[j] == 0 ) {
				dbg_printf("Map found in page slot %i\n", i);
				map_found = i;
			}
		}
		if ( map_found >= 0 ) {
			extension_info_t *tmp;
			dbg_printf("Move map from page slot %i to slot %i\n", map_found ,map_id);
	
			// exchange the two maps
			tmp = extension_map_list->slot[map_id];
			extension_map_list->slot[map_id] = extension_map_list->page[map_found];
			extension_map_list->slot[map_id]->map->map_id = map_id;

			extension_map_list->page[map_found] = tmp;
			extension_map_list->page[map_found]->map->map_id = map_found;
			return 1;
			
		} else {
			dbg_printf("Map not found in extension page\n");
			// map not found - move it to the extension page to a currently free slot
			if ( next_free < MAX_EXTENSION_MAPS ) {
				dbg_printf("Move existing map from slot %d to page slot %d\n",map_id, next_free);
				extension_map_list->page[next_free]   	= extension_map_list->slot[map_id];
				extension_map_list->page[next_free]->map->map_id = next_free;
				extension_map_list->slot[map_id] 		= NULL;
				// ready to fill new slot
			} else {
				fprintf(stderr, "Extension map list exhausted - too many extension maps ( > %d ) to process;\n", MAX_EXTENSION_MAPS);
				exit(255);
			}
		}
	}

	// add new entry to slot
	extension_map_list->slot[map_id]	= (extension_info_t *)calloc(1,sizeof(extension_info_t));
	if ( !extension_map_list->slot[map_id] ) {
		fprintf(stderr, "calloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		exit(255);
	}
	extension_map_list->slot[map_id]->map   = (extension_map_t *)malloc((ssize_t)map->size);
	if ( !extension_map_list->slot[map_id]->map ) {
		fprintf(stderr, "malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		exit(255);
	}
	memcpy((void *)extension_map_list->slot[map->map_id]->map, (void *)map, map->size);

	extension_map_list->slot[map_id]->ref_count = 0;

	if ( map_id > extension_map_list->max_used ) {
		extension_map_list->max_used = map_id;
	}

	// Update next_free page slot, if it's used now
	while ( extension_map_list->page[next_free] && (next_free < MAX_EXTENSION_MAPS))
		next_free++;
	extension_map_list->next_free = next_free;

	// if all slots are exhausted next_free is now MAX_EXTENSION_MAPS. The next time an empty slot is needed, it will properly fail.
	dbg_printf("Installed map in slot %d. Next free page slot: %d\n", map_id, next_free);
	
	//map changed
	return 1;

} // End of Insert_Extension_Map

void PackExtensionMapList(extension_map_list_t *extension_map_list) {
int i, free_slot;

	dbg_printf("Pack extensions maps\n");
	// compact extension map list - close gaps
	free_slot = -1;
	for ( i=0; i <= extension_map_list->max_used; i++ ) {
		dbg_printf("Check slot: %i, ref: %u\n", i, extension_map_list->slot[i] ? extension_map_list->slot[i]->ref_count : 0);
		if ( extension_map_list->slot[i] != NULL && extension_map_list->slot[i]->ref_count == 0 ) {
			// Destroy slot, if no flows referenced this map
			free(extension_map_list->slot[i]->map);
			free(extension_map_list->slot[i]);
			extension_map_list->slot[i] = NULL;
			dbg_printf("Free slot: %i\n", i);
		}
		if ( extension_map_list->slot[i] == NULL && free_slot == -1 ) {
			// remember this free slot
			dbg_printf("Remember free slot at %i\n", i);
			free_slot = i;
		} else if ( free_slot != -1 && extension_map_list->slot[i] != NULL ) {
			int j;
			// move this slot down to compact the list
			extension_map_list->slot[free_slot] = extension_map_list->slot[i];
			extension_map_list->slot[free_slot]->map->map_id = free_slot;
			extension_map_list->slot[i] = NULL;
			dbg_printf("Move slot %i down to %i\n", i, free_slot);

			// search for next free slot - latest slot[i] is free now
			for ( j = free_slot + 1; j <= i; j++ ) {
				if ( extension_map_list->slot[j] == NULL ) {
					free_slot = j;
					dbg_printf("Next free slot found at %i\n", free_slot);
					break;
				}
			}
		} else {
			dbg_printf("Fell through\n");
		}
	}

	// get max index - set index to map
	i = 0;
	while ( extension_map_list->slot[i] != NULL && i < MAX_EXTENSION_MAPS ) {
		dbg_printf("Slot: %i, ref: %u\n", i, extension_map_list->slot[i]->ref_count);
		i++;
	}

	if ( i == MAX_EXTENSION_MAPS ) {
		// ups! - should not really happen - so we are done for now
		if ( extension_map_list->next_free == 0 ) {
			// map slots full but no maps im page list - we are done
			return;
		} else {
			// we can't handle this event for now - too many maps - but MAX_EXTENSION_MAPS should be more than enough
			fprintf(stderr, "Critical error in %s line %d: %s\n", __FILE__, __LINE__, "Out of maps!" );
			exit(255);
		}
	}

	// this points to the next free slot
	free_slot = i;

	for ( i=0; i < extension_map_list->next_free; i++ ) {
		if ( free_slot < MAX_EXTENSION_MAPS ) {
			if ( extension_map_list->page[i]->ref_count ) {
				dbg_printf("Move page %u to slot %u\n", i, free_slot);
				extension_map_list->slot[free_slot] = extension_map_list->page[i];
				extension_map_list->slot[free_slot]->map->map_id = free_slot;
				extension_map_list->page[i] = NULL;
				free_slot++;
			} else {
				dbg_printf("Skip page %u. Zero ref count \n", i);
			}
		} else {
			// we can't handle this event for now, but should not happen anyway
			fprintf(stderr, "Critical error in %s line %d: %s\n", __FILE__, __LINE__, "Out of maps!" );
			exit(255);
		}
	}

	extension_map_list->max_used = free_slot - 1;
	dbg_printf("Packed maps: %i\n", free_slot);

#ifdef DEVEL
	// Check maps
	i = 0;
	while ( extension_map_list->slot[i] != NULL && i < MAX_EXTENSION_MAPS ) {
		if ( extension_map_list->slot[i]->map->map_id != i ) 
			printf("*** Map ID missmatch in slot: %i, id: %u\n", i, extension_map_list->slot[i]->map->map_id);
		i++;
	}
#endif

} // End of PackExtensionMapList

void SetupExtensionDescriptors(char *options) {
int i, *mask;
char *p, *q, *s;

	Max_num_extensions = 0;
	i = 1;
	while ( extension_descriptor[i++].id ) 
		Max_num_extensions++;

	mask = (int *)calloc(Max_num_extensions+1, sizeof(int));
	if ( !mask ) {
		fprintf(stderr, "malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		exit(255);
	}

	s = (char *)malloc(strlen(options));
	if ( !s ) {
		fprintf(stderr, "malloc() error in %s line %d: %s\n", __FILE__, __LINE__, strerror(errno) );
		exit(255);
	}
	q = s;
	*q = '\0';
	p = options;
	while ( *p ) {
		if ( !isspace(*p) )
			*q++ = *p;
		p++;
	}
	*q = '\0';

	p = s;
	while ( p && *p ) {
		int sign;
		q = strchr(p, ',');
		if ( q )
			*q++ = '\0';
		
		// get possible sign
		sign = 1;
		if ( *p == '-' ) {
			sign = -1;
			p++;
		}
		if ( *p == '+' ) {
			sign = 1;
			p++;
		}

		if ( strcmp(p, "all") == 0 ) {
			for (i=4; i<= Max_num_extensions; i++ ) 
				extension_descriptor[i].enabled = sign == 1 ? : 0;
		} else {
			switch ( *p ) {
				case '\0':
					fprintf(stderr, "Extension format error: Unexpected end of format.\n");
					exit(255);
					break;
				case '*': 
					for (i=4; i<= Max_num_extensions; i++ ) 
						extension_descriptor[i].enabled = sign == 1 ? : 0;
					break;
				default: {
					int i = strtol(p, NULL, 10);
					if ( i == 0 ) {
						fprintf(stderr, "Extension format error: Unexpected string: %s.\n", p);
						exit(255);
					}
					if ( i > Max_num_extensions ) {
						fprintf(stderr, "Extension format error: Invalid extension: %i\n", i);
						exit(255);
					}
					mask[i] = sign;
				}
					
			}
		}
		p = q;
	}
	for (i=4; i<= Max_num_extensions; i++ ) {
		int ui = extension_descriptor[i].user_index;

		// mask[ui] == 0 means no input from user -> default behaviour or already overwritten by '*' 
		if ( mask[ui] < 0 ) {
			extension_descriptor[i].enabled = 0;
		}
		if ( mask[ui] > 0 ) {
			extension_descriptor[i].enabled = 1;
		}
		if ( extension_descriptor[i].enabled ) {
			dbg_printf("Add extension: %s\n", extension_descriptor[i].description);
			syslog(LOG_INFO, "Add extension: %s", extension_descriptor[i].description);
		}
	}

	free(mask);

} // End of SetupExtensionDescriptors

void PrintExtensionMap(extension_map_t *map) {
int i;

	printf("Extension Map:\n");
	printf("  Map ID   = %u\n", map->map_id);
	printf("  Map Size = %u\n", map->size);
	printf("  Ext Size = %u\n", map->extension_size);
	i=0;
	while (map->ex_id[i]) {
		int id = map->ex_id[i++];
		printf("  Index %3i, ext %3u = %s\n", extension_descriptor[id].user_index, id, extension_descriptor[id].description );
	}
	printf("\n");

} // End of PrintExtensionMap

int VerifyExtensionMap(extension_map_t *map) {
int i, failed, extension_size, max_elements;

	failed = 0;
	if (( map->size & 0x3 ) != 0 ) {
		printf("Verify map id %i: WARNING: map size %i not aligned!\n", map->map_id, map->size);
		failed = 1;
	}

	if ( ((int)map->size - (int)sizeof(extension_map_t)) <= 0 ) {
		printf("Verify map id %i: ERROR: map size %i too small!\n", map->map_id, map->size);
		failed = 1;
		return 0;
	}

	max_elements = (map->size - sizeof(extension_map_t)) / sizeof(uint16_t);
	extension_size = 0;
	i=0;
    while (map->ex_id[i] && i <= max_elements) {
        int id = map->ex_id[i];
		if ( id > Max_num_extensions ) {
			printf("Verify map id %i: ERROR: element id %i out of range [%i]!\n", map->map_id, id, Max_num_extensions);
			failed = 1;
		}
        extension_size += extension_descriptor[id].size;
        i++;
    }

	if ( (i != max_elements ) && ((max_elements-i) != 1) ) {
		// off by 1 is the opt alignment
		printf("Verify map id %i: ERROR: Expected %i elements in map, but found %i!\n", map->map_id, max_elements, i);
		failed = 1;
	}

	return failed;

} // End of VerifyExtensionMap


void DumpExMaps(char *filename) {
int i, rfd, done;
stat_record_t *stat_ptr;
data_block_header_t in_block_header;					
common_record_t *flow_record, *in_buff;
char	*string;
uint32_t skipped_blocks;
uint64_t total_bytes;

	Max_num_extensions = 0;
	i = 1;
	while ( extension_descriptor[i++].id ) 
		Max_num_extensions++;

	printf("\nDump all extension maps:\n");
	printf("========================\n");

	rfd = OpenFile(filename, &stat_ptr, &string);
	if ( rfd < 0 ) {
		fprintf(stderr, "%s\n", string);
		return;
	}

	// allocate buffer suitable for netflow version
	in_buff = (common_record_t *) malloc(BUFFSIZE);

	done = 0;
	while ( !done ) {
	int i, ret;

		// get next data block from file
		ret = ReadBlock(rfd, &in_block_header, (void *)in_buff, &string);

		switch (ret) {
			case NF_CORRUPT:
			case NF_ERROR:
				if ( ret == NF_CORRUPT ) 
					fprintf(stderr, "Corrupt data file '%s': '%s'\n",filename, string);
				else 
					fprintf(stderr, "Read error in file '%s': %s\n",filename, strerror(errno) );
				done = 1;
				continue;
				break;
				// fall through - get next file in chain
			case NF_EOF:
				done = 1;
				continue;
				break;
	
			default:
				// successfully read block
				total_bytes += ret;
		}

		if ( in_block_header.id != DATA_BLOCK_TYPE_2 && in_block_header.id != DATA_BLOCK_TYPE_1 ) {
			fprintf(stderr, "Can't process block type %u. Skip block.\n", in_block_header.id);
			skipped_blocks++;
			continue;
		}

		flow_record = in_buff;
		for ( i=0; i < in_block_header.NumRecords; i++ ) {
			if ( flow_record->type == ExtensionMapType ) {
				extension_map_t *map = (extension_map_t *)flow_record;
				VerifyExtensionMap(map);
				PrintExtensionMap(map);
			}

			// Advance pointer by number of bytes for netflow record
			flow_record = (common_record_t *)((pointer_addr_t)flow_record + flow_record->size);	
		}
	}

	close(rfd);
	free(in_buff);

} // End of DumpExMaps

