/*
 *  Copyright (c) 2012, Gerard Wagener
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
 *   * Neither the name of Gerard Wagener nor the names of its contributors may be 
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
#ifndef _LIBNFREADER_H
#define _LIBNFREADER_H 1

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <libnfdump/nffile.h>
typedef struct libnfstates {
    master_record_t master_record;
    data_block_header_t block_header;
    common_record_t     *flow_record;
    common_record_t     *in_buff;
    uint32_t	buffer_size;
    int 		i;
    int         rfd;
    int         done;
    int         ret;
    char		*string;
    #ifdef COMPAT15
    int	v1_map_done = 0;
    #endif
    int inblock; /* Marker to determine if in netflow block */
    int records_present; /* State if records are present */
} libnfstates_t;

void print_record(void *record);

libnfstates_t* initlib(char* Mdirs, char* rfile, char* Rfile);

void libcleanup(libnfstates_t* states);

master_record_t* get_next_record(libnfstates_t* states);

#ifdef __cplusplus
}
#endif

#endif
