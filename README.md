libnfdump
=========

libnfdump - library to natively access netflow records stored by nfcapd


The program nfreader of nfdump-1.6.2 has been mutated to a library. The
goal is to access directly from external programs to the master_record_t
structure without having to pass through standard output and standard 
input or other temporary files.

Building libnfdump
==================

nfdump-1.6.2$ ./configure --enable-libnfdump

nfdump-1.6.2$ make

nfdump-1.6.2$ make install


Testing libnfcapd
=================
nfdump-1.6.2/bin/testlibnfdump <full_path_to_library> <nfcapd_file>


Functions
=========

libnfstates_t* initlib(char* Mdirs, char* rfile, char* Rfile);

master_record_t* get_next_record(libnfstates_t* states);

void libcleanup(libnfstates_t* states);


Description
===========

The initlib functions returns a structure of states of an instance of libnfdump. 
On errors NULL is returned. The function get_next_record returns the 
next encountered record.  If there are no records NULL is returned.

More details can be found in the libnfdump wiki.
https://github.com/haegardev/libnfdump/wiki

 
 
