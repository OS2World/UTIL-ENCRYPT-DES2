/* Data Encryption Standard front end
 * Usage: des [-e -d] keyvalue infile outfile
 */
#define INCL_BASE
#include <os2.h>
#include <stdio.h>
#include <string.h>
#include "des.h"


VOID main(int argc, CHAR *argv[])
{
FILE *fi, *fo;
CHAR key[9];
CHAR blk[8];

if (argc > 4)
   {
     strncpy(key, argv[2], 8);
     key[8] = '\0';
     setparity(key);

     initkey(key);
    if ((fi = fopen(argv[3], "rb")) != NULL)
       {
        if ((fo = fopen(argv[4], "wb")) != NULL)
           {
            while (!feof(fi))
               {
                memset(blk, 0, 8);
                if (fread(blk, 1, 8, fi) != 0)
                   {
                    if (stricmp(argv[1], "-e") == 0)
                        encrypt(blk);
                    else
                        decrypt(blk);
                   fwrite(blk, 1, 8, fo);
                   }
               }
           fclose(fo);
           }
       fclose(fi);
       }
   }
else
    printf("\nUsage: des [-e -d] keyvalue infile outfile");
}
