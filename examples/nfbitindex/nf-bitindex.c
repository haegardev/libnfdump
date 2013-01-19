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
 * TODO implement append mode 
 * TODO implement shm support
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
#include <getopt.h>
#include <arpa/inet.h>
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
        hdr->firstseen.tv_sec = 0xFFFFFFFF;
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
int index_nfcapd_file(char* filename, ipv4cache_hdr_t* hdr, uint8_t* bitindex)
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
                /* Sometimes the order of the nfcapd files is not assured
                 * The first flow record in an nfcapd file does not necessary have the oldest timestamp
                 * The last flow record in an nfcapd file is not necessary the youngest.
                 * FIXME If the timestamps are equal, the usec are not properly updated
                 */ 
                 
                if (rec->first < hdr->firstseen.tv_sec) {
                    /* This flow is older than all the other flows seen before */
                    hdr->firstseen.tv_sec = rec->first;
                    hdr->firstseen.tv_usec = rec->msec_first;
                }
                if (rec->last > hdr->lastseen.tv_sec) {
                    /* This flow more recent than all the other observed flows */
                    hdr->lastseen.tv_sec = rec->last;
                    hdr->lastseen.tv_usec = rec->msec_last;
                }
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
            if (r == SPACE_SIZE) {
                out = 1;
            }else{
                fprintf(stderr,"Could not store bitindex");
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

void usage(void)
{
    printf("nf-bitindex - Put IPv4 addresses extracted from nfcapd files in a bitindex\n");
    printf("\n");
    printf("nf-bitindex [-h] [-l -w <filename>] [ -q -r <filename> ] \n");
    printf("\n");
    printf("OPTIONS\n");
    printf("\n");
    printf("    -h --help   Shows this screen\n");
    printf("    -b --batch  Read nfcapd files from standard input that are indexed\n");
    printf("    -w --write  Specify the filename where the bitindex is stored\n");    
    printf("    -s --source Specify a source to identify the netflow records\n");
    printf("    -q --query  Query if the ip addresses read through standard input are \n");
    printf("                in the bitindex. The result is outputed on standard output. \n");
    printf("    -r --read   Read a gzip compressed bitindex\n");
    printf("\n");
    printf("EXAMPLE\n");
    printf("    Put all the nfcapd files from Septembre 2012 in a bitindex\n\n");
    printf("find . | grep \"nfcapd.201209\" | nf-bitindex -b -w september2012.ibi.gz -s router_1\n\n"); 
    printf("QUERY INPUT FORMAT\n\n");
    printf("IP addresses should be passed as list (delimited with a \\n) in dotted decimal notation\n\n");
    printf("QUERY OUTPUT FORMAT\n");
    printf("\n");
    printf("xxx.xxx.xxx.xxx source firstseen lastseen\n\n");
    printf("xxx.xxx.xxx.xxx is an IPv4 address\n");
    printf("source is the source that generated the netflow records\n");
    printf("firstseen indicates the oldest timestamp of *ANY* netflow record present in this index\n");
    printf("lastseen indicates the youngest timestamp of *ANY* netflow record presented in this index\n");
    printf("Hence, the right file must be still searched!\n\n");
    printf("AUTHOR\n");
    printf("    Gerard Wagener\n");
    printf("\n");
    printf("LICENSE\n");
    printf("    GNU Affero General Public License\n");
}

/* Read files from standard input and put them in the bitindex file  
 * identified with the targetfile parameter.
 * returns EXIT_SUCCESS on success and EXIT_FAILURE on errors.
 */
int batch_processing(char *source, char* targetfile)
{
    int i,r;
    char *filename;
    uint8_t* bitindex;
    ipv4cache_hdr_t* hdr;
 
    assert(source && targetfile);
    r = EXIT_FAILURE; /* Return code */
    /* FIXME assume that the timezone of the netflow collector is the same
     * than the timezone configured on this machine
     */
    if (!(hdr = create_local_header(source)))
        goto out;
    
    if (!(bitindex = bitindex_new(SPACE)))
       goto out;
 
    filename = calloc(1024,1);
    if (!filename)  
        goto out;
 
    while (fgets(filename, 1024, stdin)){
        filename[1023] = 0;
        /* remove new line */
        for (i=0; i<1024; i++){
            if (filename[i] == '\n'){
                filename[i] = 0;
                break;
            }
        }
        printf("[INFO] Processing %s\n",filename);
        if (!index_nfcapd_file(filename, hdr, bitindex)){
            printf("[ERROR] Could not process %s\n",filename);
        }
    }
    printf("[INFO] Creating %s\n",targetfile);
    if (store_bitindex(targetfile, hdr, bitindex)){
        r = EXIT_SUCCESS;
    } else {
        printf("[ERROR] Could not store bitindex in file %s\n",targetfile);
        r = EXIT_FAILURE;
    }    
out:
    if (hdr)
        free(hdr);
    if (bitindex)
        free(bitindex);
    if (filename)
        free(filename);
    return r;                          
}

int query_addr (char* sourcefile)
{
    char *istr;
    int i,r;
    uint32_t addr;
    ipv4cache_hdr_t* hdr;
    uint8_t* bitindex;
    r = EXIT_FAILURE;
    istr  = calloc(64,1);
    if (!istr)
        goto oret;
    
    bitindex = bitindex_new(SPACE);
    if (!bitindex)
        goto oret;

    hdr = load_bitindex(sourcefile, bitindex);
    if (!hdr)
        goto oret;

    while (fgets(istr, 64, stdin)){
        istr[63] = 0;
        /* Replace the new line */
        for (i=0; i<64;i++){
            if (istr[i] == '\n'){
                istr[i] = 0;
                break;
            }
        }
        addr = 0; //FIXME check endianess 
        if (inet_pton(AF_INET, istr,&addr)){ 
            if (test_bit(bitindex, addr)){
                printf("%s %s %d %d\n",istr, hdr->source[0], 
                                      (uint32_t)hdr->firstseen.tv_sec, 
                                      (uint32_t)hdr->lastseen.tv_sec); 
            }
        }else{
            fprintf(stderr,"The string %s is not a valid IP address\n",istr);
        }
    }
    /* Here every thing is assumed to be fine */
    r = EXIT_SUCCESS;
oret:
    if (istr)
        free(istr);
    if (bitindex)
        free(bitindex);
    if (hdr)
        free(hdr);    
    return r;
}

int main(int argc, char* argv[])
{
    int next_option = 0;
    const char* const short_options = "hw:bs:r:q";
    const struct option long_options[] = {
                { "help", 0, NULL, 'h' },
                { "batch", 0, NULL, 'b' },
                { "write", 1, NULL, 'w' },
                { "source",1, NULL, 'b' },
                { "query",0,NULL, 'b'},
                { "read",1,NULL,'q'},
                {NULL,0,NULL,0}};
    char* targetfile;
    char * source;
    char *sourcefile;
    int batch,query;
    batch = 0;
    query = 0;
    targetfile = NULL;
    source = NULL;
    do {
        next_option = getopt_long (argc, argv, short_options, 
                                   long_options, NULL);
        if (next_option > 0) {
            switch(next_option)
            {
            case 'h':
                usage();
                return EXIT_SUCCESS;
            case 'b':
                batch = 1;
                break;
            case 'w':
                targetfile = optarg;
                break;
            case 's':
                source = optarg;
                break;
            case 'r':
                sourcefile = optarg;
                break;
            case 'q':
                query = 1;
                break;
            default:
                return EXIT_FAILURE;
            }
        }
    }while (next_option != -1);
 
    /* test parameters */
    if (!batch) {
        if (!query) {
            printf("Nothing to do.\n");
            return EXIT_SUCCESS;
        }
    }
    if (query & batch) {
        fprintf(stderr,"Batch processing and query mode are mutal exclusive.\n");
        return EXIT_FAILURE;
    }
    if (batch & (!targetfile)){
        fprintf(stderr, "A target file has to be specified with the -w option\n");
        return EXIT_FAILURE;
    }

    if (batch & (!source)) {
        fprintf(stderr,"A source must be specified with the -s option\n");
        return EXIT_FAILURE;
    }

    if (query & (!sourcefile)) {
        fprintf(stderr, "In query mode, a source file must be specified with the -r option\n");
        return EXIT_FAILURE;
    }
    /* Do the work */
    if (batch)
        return batch_processing(source, targetfile);
   
    if (query)
        return query_addr(sourcefile); 
    return EXIT_SUCCESS;
}
