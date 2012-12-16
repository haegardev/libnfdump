libnfdump
=========

libnfdump - library to natively access netflow records stored by nfcapd


The program nfreader of nfdump-1.6.2 has been mutated to a library.

Building libnfdump
==================

nfdump-1.6.2$ ./configure
nfdump-1.6.2$ make
nfdump-1.6.2/bin/buildlibnfdump.sh

In the directory nfdump-1.6.2/bin/ the library libnfdump.so should appear.


Testing libnfcapd
=================
nfdump-1.6.2/bin/testlibnfdump <full_path_to_library> <nfcapd_file>


Functions
=========

libnfstates_t* initlib(char* Mdirs, char* rfile, char* Rfile);
master_record_t* get_next_record(libnfstates_t* states);
void libcleanup(libnfstates_t* states);

The initlib functions returns a structure of states of an instance of libnfdump. 
On errors NULL is returned. The function get_next_record returns the 
next enountered record.  If there are no records NULL is returned.
 
