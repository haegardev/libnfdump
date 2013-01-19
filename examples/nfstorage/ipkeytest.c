//Problem how to efficiently compare IPv6 and IPv4 addresses?
//The uinion addr_s seems to solve the problem
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
typedef union addr_s {
        uint32_t ipv4;
        uint64_t ipv6[2];
} addr_t;

//Compare the two uint64_t values 
int main(int argc, char* argv[])
{
    addr_t a,b;
    bzero(&a,sizeof(addr_t));
    bzero(&b,sizeof(addr_t));
    
    /* Addresses of ip address a
     * printf("a.ipv4 %p\n",&(a.ipv4));
     * printf("a.ipv6[0] %p\n",&(a.ipv6[0]));
     * printf("a.ipv6[1] %p\n",&(a.ipv6[1]));
     * a.ipv4 0xbf84dab0     -> at the root of the union
     * a.ipv6[0] 0xbf84dab0  -> at the root of the union
     * a.ipv6[1] 0xbf84dab8  -> root + 8 bytes (uint64_t)
     * 
     * When a IP address is used as key in a list we don't need to care 
     * if it is an IPv4 or IPv6 address
     */

     /* a.ipv4 = 2345;
      * b.ipv4 = 2345;  --> both addresses are equal
      * 
      *
      * a.ipv4 = 2345; --> both addresses differ
      * b.ipv4 = 2344;  
      *
      *
      * a.ipv6[0] = 123456666; --> both addresses are equal
      * a.ipv6[1] = 987623;
      * b.ipv6[0] = 123456666;
      * b.ipv6[1] = 987623;
      *
      * a.ipv6[0] = 123456666; --> ip addresses differ
      * a.ipv6[1] = 987623;
      * b.ipv6[0] = 123456666;
      * b.ipv6[1] = 987613; -> here a small swap
      *
      * a.ipv6[0] = 23456666; --> a small change and IP addresses differ
      * a.ipv6[1] = 987623;
      * b.ipv6[0] = 123456666;
      * b.ipv6[1] = 987623;
      */

      a.ipv4 = 1;
      b.ipv4 = 1;
       
      if ((a.ipv6[0] == b.ipv6[0]) && a.ipv6[1] == b.ipv6[1]) {
         printf("IP addresses are equal\n");
       }else{
         printf("IP addresses differ\n");
      }
    return EXIT_SUCCESS; 
}
