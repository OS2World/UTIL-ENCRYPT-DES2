#define INCL_BASE
#include <os2.h>
#include <stdio.h>
#include <stdlib.h>
SHORT EXPENTRY EncryptData(CHAR *key, CHAR *data, SHORT length) ;
SHORT EXPENTRY DecryptData(CHAR *key, CHAR *data, SHORT length) ;

main(int argc, char *argv[], char *envp[])
{
static CHAR mytext[40] ;
SHORT x ;
if(argc < 2)
    return 0 ;
strncpy(mytext, argv[1], 40) ;
x = strlen(mytext) + ((strlen(mytext) % 8));
printf("%s\n", mytext) ;
EncryptData("10000000", mytext, x) ;
DecryptData("10000000", mytext, x) ;
printf("%s\n", mytext) ;
}
