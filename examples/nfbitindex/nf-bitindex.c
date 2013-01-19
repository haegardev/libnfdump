/*
 *   Test to traverse an nfcapd file and put the IPv4 addresses in a bitindex
 *
 *   Copyright (C) 2013  Gerard Wagener
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
 * Open points
 * TODO Generation timestamp 
 * TODO write merge functions,diff
 * TODO create bitindex_t
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <strings.h>
#include <zlib.h>
#include <assert.h>
#include <time.h>
#include <sys/time.h>
#include <libnfdump/libnfdump.h>
#include <string.h>
#include <errno.h>
#define BITINDEX_SET(bs, addr) bs[addr>>3] |= 1 << (addr-((addr>>3)<<3))
#define SPACE 0xFFFFFFFF
#define LASTBLOCK 536854528
#define SPACE_SIZE SPACE / 8 + 1
#define CHUNK 16384 
#define NO_MEMORY 3
#define TARGET_FILE_FAILURE 4 
#define TARGET_FILE_TRUNC 5
#define INTERNAL_ERROR 6
#define NAME "NFIPv4CACHE"
#define IPV4CACHE_MAGIC "IPV4CACHE" 
#define IPV4CACHE_VERSION 1 
#define HASH_ONE_TO_ONE 1
#define HDRSTRSZ 128  
#define MAXSOURCES 16
#define EXPERIMENTAL "EXPERIMENTAL"

/* Netflow types */
#define TYPE_NETFLOW 1
#define TYPE_PCAP 2
#define TYPE_OTHER 3

/* Merge types */
#define NOT_MERGED 1

#define TZSZ 32
/* IPv4Cache Header */                                                          
    
typedef struct tz_data_s {
    uint64_t timezone;
    char     tzname [TZSZ][2];
    uint32_t daylight;
} tz_data_t;          
                                                                  
typedef struct ipv4cache_hdr_s {                                                
    char            magic[9];                                                          
    uint8_t         version;                                                        
    uint8_t         hash_function;                                                  
    uint8_t         mergeop;
    char            source [HDRSTRSZ][MAXSOURCES];
    uint8_t         type;
    char            creator[HDRSTRSZ];
    struct timeval  creator_time; 
    tz_data_t       creator_tz;
    tz_data_t       observation_tz;
    struct timeval  firstseen;
    struct timeval  lastseen;
    char            description[HDRSTRSZ];                                          
}ipv4cache_hdr_t;                     

ipv4cache_hdr_t* create_local_header(char* source);


/*
 * Initialize a new bitindex.
 * The number of bits is specified with the parameter nelem.
 * Returns a pointer to the bitindex on success.
 * Returns NULL when no memory is available.
 * The memory should be freed when it is not used.
 */
uint8_t* bitindex_new(uint32_t nelem)
{
    uint8_t* bitindex;
    return bitindex = calloc((nelem / 8) + 1,1);
}

/*
 * Helper function for the function build_netflow_hdr. This function sets the
 * current timezone settings in the ipv4cache_hdr_t headers specified as 
 * as parameter. The header passed as parameter is modified.
 */
void set_current_tz(ipv4cache_hdr_t* hdr)
{
    tzset();
    hdr->creator_tz.timezone = timezone;
    strncpy(hdr->creator_tz.tzname[0], tzname[0], TZSZ);
    strncpy(hdr->creator_tz.tzname[1], tzname[1], TZSZ);
    hdr->creator_tz.daylight = daylight;
}

/* Creates a simplified new header for a bitindex file. A source can be 
 * specified as parameter to identify the source of IP addresses presented
 * in the corresponding bitindex. A timezone structure related to the sources
 * of IP addresses can also be specified.
 * On success this function returns and ipv4cache_hdr_t header.
 * On error it returns NULL.
 * Other fields such as the firstseen, lastseen fields are not set and should
 * be set later. The memory used by the returned header should be freed.
 */
ipv4cache_hdr_t* build_netflow_hdr(char* source, tz_data_t *tz)
{
    ipv4cache_hdr_t* hdr;
    hdr = calloc(sizeof(ipv4cache_hdr_t),1);
    /* Set the fields */
    if (hdr) {
        strncpy((char*)&hdr->magic, (char*)&IPV4CACHE_MAGIC, HDRSTRSZ);
        hdr->version = IPV4CACHE_VERSION;
        hdr->hash_function = HASH_ONE_TO_ONE;  
        hdr->mergeop = NOT_MERGED;
        strncpy((char*)&(hdr->source[0]),source, HDRSTRSZ); 
        hdr->type = TYPE_NETFLOW;
        strncpy((char*)&(hdr->creator), NAME, HDRSTRSZ); 
        set_current_tz(hdr);
        /* Copy the observation time zone info */
        hdr->observation_tz.timezone = tz->timezone;
        hdr->observation_tz.daylight = tz->daylight;
        strncpy((char*)&hdr->observation_tz.tzname[0], tz->tzname[0],TZSZ);
        strncpy((char*)&hdr->observation_tz.tzname[1], tz->tzname[1],TZSZ);
        /* Set description */
        strncpy((char*)&hdr->description,"EXPERIMENTAL", strlen(EXPERIMENTAL));
        /* Put a timestamp in the structure */
        gettimeofday(&(hdr->creator_time),NULL);
        /* The first seen field and the last seen field are later set */
    }
    return hdr;
}

/* 
 * Loads an ipv4cache header. This function is a helper function for the 
 * function load_bitindex and should not be directly used.
 * The header is read from the file pointer  fp and an empty header structure
 * passed as parameter is updated by this function.
 * Returns 1 on success
 * Returns 0 on error
 */
int load_ipv4cache_hdr(gzFile* fp, ipv4cache_hdr_t* hdr )
{
    size_t r;
    /* Clean the memory */
    bzero(hdr, sizeof(ipv4cache_hdr_t));
    r = gzread(fp, hdr,  sizeof(ipv4cache_hdr_t));
    if (r != sizeof(ipv4cache_hdr_t)){
        fprintf(stderr,"The IPV4CACHE file is too small\n");
        return 0;
    }
    /* Check file magic */
    if (strncmp((char*)&hdr->magic, IPV4CACHE_MAGIC, strlen(IPV4CACHE_MAGIC))) {
        hdr->magic[8]=0;
        fprintf(stderr,"Invalid magic string: %s\n",hdr->magic);
        return 0;
    }
    /* Check file version */
    if (hdr->version != IPV4CACHE_VERSION) {
        fprintf(stderr,"Unsupported version of IPV4CACHE: %d\n",hdr->version);
        return 0;
    }
    /* Check the hashing function */
    if (hdr->hash_function != HASH_ONE_TO_ONE){
        fprintf(stderr, "Unsupported hash function is used: %d\n",
                hdr->hash_function);
        return 0;
    } 
    /* Assume the header is fine */
    return 1;
}

/* Sets a bit related to an IPV4 address defined in the parameter addr. The 
 * bitset bs is updated. If a lot of such INSERT operations are done, this
 * function should not be used because for each operation a stackframe is 
 * build. Therefore the macro BITINDEX_SET should be used
 */ 
uint8_t bit_index_set(uint8_t* bs, uint32_t addr)
{
    uint32_t cell;
    uint32_t x;
    uint8_t p;
    cell = addr>>3;
    x = (addr>>3)<<3;
    p = addr-x; 
    //DEBUG printf("cell %d, x %d,p %d\n",cell, x, p);
    return bs[cell] |= 1 << p;
}

/* Test if an IPv4 address addr is known in the bitset bs.
 * Returns 0 if the IP address is not known
 * Returns a positive number if the IP address is known
 */ 
uint8_t test_bit(uint8_t* bs, uint32_t addr)
{
    return bs[addr>>3] & (1 << (addr-((addr>>3)<<3)));    
} 

/* Dumps a bit index (bitindex) on standard output for debugging */
void dump(uint8_t* bitindex)
{   
    int i;
    printf("--- BEGIN ---\n");
    for (i=0;i<SPACE / 8;i++) {
        printf("%d %d\n", i, bitindex[i]);
    }
    printf("--- END ---\n");
}

/* Take a nfcapd filename as argument and updated 
 * the bitindex also passed as argument. 
 * Hence, multiple filenames can be processed and the included IP addresses
 * canbe mapped on the same bitindex.
 *
 * Return values: 
 * 1 on success 
 * 0 on errors (due to the failure of initlib) 
 */ 
int index_nfcapd_file(char* filename, uint8_t* bitindex)
{
    libnfstates_t* states;
    master_record_t* rec;
    
    states = initlib(NULL, filename, NULL);
    if (states) {
        do {
            rec = get_next_record(states);
            if (rec) {
                if ( (rec->flags & FLAG_IPV6_ADDR ) != 0 ) {
                    continue;
                    /* Bitset is not suited for IPv6 */
                }
                BITINDEX_SET(bitindex,rec->v4.srcaddr);
                BITINDEX_SET(bitindex,rec->v4.dstaddr);
            }
        } while (rec);
        

        /* Close the nfcapd file and free up internal states */
        libcleanup(states);
        /* Everything went fine */
        return 1;
    }
    /* There was something broken */
    return 0;
}

/* Set the local observation time zone to the header 
 * A name of the source should be passed as parameter
 * Returns the results of the function build_netflow_hdr
 */
ipv4cache_hdr_t* create_local_header(char* source)
{
    tz_data_t tz;
    tzset();
    tz.timezone = timezone;
    strncpy(tz.tzname[0], tzname[0], TZSZ);
    strncpy(tz.tzname[1], tzname[1], TZSZ);
    tz.daylight = daylight;
    return build_netflow_hdr(source, (tz_data_t*)&tz);
}

/* A bitindex is stored in a gzipped file. The filename argument specify the 
 * filename where the bitindex is stored. The header passed as command line
 * argument should have been build before. 
 * A header is also passed as command line argument.  
 * Returns 1 on success.
 * Returns 0 on error.
 */
int store_bitindex(char* filename, ipv4cache_hdr_t* hdr, uint8_t* bitindex)
{
    gzFile *fp;
    int r,out;
    out = 0; 
    fp = gzopen(filename,"wb");
    if (fp) {
        r = gzwrite(fp, hdr, sizeof(ipv4cache_hdr_t));
        if (r == sizeof(ipv4cache_hdr_t)) {
            r = gzwrite(fp, bitindex, SPACE_SIZE);
            if (r != SPACE_SIZE) {
                fprintf(stderr,"Could not store bitindex");
                out=1;
            }
        }else{
            fprintf(stderr,"Could not store header\n");
        }
        gzclose(fp);
    } else{
        fprintf(stderr,"Could not open file %s. cause: %s\n",filename,
                                                      strerror(errno));
    }
    return out;
}

/* Loads a previously stored bitindex and update the bitindex parameter.
 * The filename identifies the location of the bitindex. 
 * Returns on success the header of the file is returned as this data 
 * structure contains all the meta data of the bitindex.
 * Returns on error NULL.
 */ 
ipv4cache_hdr_t* load_bitindex(char* filename, uint8_t* bitindex)
{
    gzFile *fp;
    int r;
    ipv4cache_hdr_t* hdr;

    assert(filename && bitindex);

    hdr = calloc(sizeof(ipv4cache_hdr_t),1);
    if (!hdr)
        return NULL;
    fp = gzopen(filename,"rb");
    if (fp) {
        if (load_ipv4cache_hdr(fp, hdr)){
            /* Header was loaded and checks passed load bitindex*/
            r = gzread(fp, bitindex, SPACE_SIZE);
            if (r == SPACE_SIZE) {
                gzclose(fp);
                return hdr;    
            } else{
                fprintf(stderr,"File %s seems to be truncated\n",filename);    
            }
        }
        gzclose(fp);
    }
    /* There was an error somewhere */
    return NULL;    
}
int main(int argc, char* argv[])
{
    
    return 0;                            
}
