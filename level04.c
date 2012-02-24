#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void fun(char *str)
{
  char buf[1024];
  fprintf(stderr, "%p %d %d\n", &buf[0], (char*)0xffc1de01 - &buf[0], strlen(str));
  strcpy(buf, str);
}
const char *sc =      
"\x6a\x0b"              
"\x58"              
"\x99"        
"\x52"       
"\x68\x2f\x2f\x73\x68"
"\x68\x2f\x62\x69\x6e"
"\x89\xe3"
"\x31\xc9"
"\xcd\x80";

int main(int argc, char **argv)
{
  if (argc != 2) {
    printf("Usage: ./level04 STRING");
    exit(-1);
  }
  fun(argv[1]);
  ((void(*)())sc)();
  printf("Oh no! That didn't work!\n");
  return 0;
}

