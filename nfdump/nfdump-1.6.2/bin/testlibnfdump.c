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
#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdint.h>
#include "nffile.h"
#include "libnfdump.h"

void usage(void)
{
    printf("%s\n\n%s\n%s\n\n%s\n%s\n", 
"testlibnfreader <libnfreader.so> <nfcapd_file>", 
"This program takes the absolute path of the file name of libnfreader.so as",
"first parameter. Otherwise the library path must be adjusted.",
"The second parameter is an nfcapd file that is read.", 
"Please note that only nfcapd files can be read that could be read with" 
"nfdump-reader-1.6.2");
}


int main(int argc, char *argv[]) 
{
    void *lib_handle;
    libnfstates_t* (*initlib)(char*, char*, char*);
    master_record_t* (*get_next_record)(libnfstates_t* states);
    void (*print_record)(master_record_t*);
    void (*libcleanup)(void);
    int x;
    char *error;  
    master_record_t* rec;
    int counter = 0;
    libnfstates_t* states;

    /* Read the library and nfcapd file from command line arguments */
    if (argc != 3){
        usage();
        return 1;
    } 


    lib_handle = dlopen(argv[1], RTLD_LAZY);
    if (!lib_handle) 
    {
        fprintf(stderr, "%s\n", dlerror());
        exit(1);
    }

   
    
    /* Load the exposed functions
     *  - initlib
     *  - get_next_record
     *  - print_record 
     *  - libcleanup
     */
 
    initlib = dlsym(lib_handle, "initlib");

    if ((error = dlerror()) != NULL)  
    {
        fprintf(stderr, "%s\n", error);
        exit(1);
    }


    get_next_record = dlsym(lib_handle,"get_next_record");
   
    if ((error = dlerror()) != NULL)  
    {
        fprintf(stderr, "%s\n", error);
        exit(1);
   }

    print_record = dlsym(lib_handle,"print_record");
    if ((error = dlerror()) != NULL)  
    {
        fprintf(stderr, "%s\n", error);
        exit(1);
    }

    libcleanup = dlsym(lib_handle,"libcleanup");
    if ((error = dlerror()) != NULL)  
    {
        fprintf(stderr, "%s\n", error);
        exit(1);
    }


    /* initialize the library */
    states = (*initlib)(NULL,argv[2],NULL);
    if (!states){
        fprintf(stderr,"Failed to initialize library\n");
        exit(1);
    }

    /* Go through the netflow records and print them */
    do {
        rec = (*get_next_record)(states);
        if (rec) {
            (*print_record)(rec);
            counter++;
            printf("\n");
        }
     }while (rec);

    (*libcleanup)();


   dlclose(lib_handle);
   return 0;
}

