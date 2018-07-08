/* ---------------------- decrypto.c ----------------------- */
/* Single key text file decryption
 * Usage: decrypto keyvalue infile outfile
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <process.h>

static char decrypt(FILE *);

static char *key = NULL;
static int keylen;
static char *cipher = NULL;
static int clen = 0, coff = 0;

void main(int argc, char *argv[])
{
   FILE *fi, *fo;
   char ch;
   int runct = 0;

   if (argc > 3)    {
       /* --- alloc memory for the key and cipher blocks --- */
       keylen = strlen(argv[1]);
       cipher = malloc(keylen+1);
       key = malloc(keylen+1);
       strcpy(key, argv[1]);

       if (cipher != NULL && key != NULL &&
               (fi = fopen(argv[2], "rb")) != NULL)    {

           if ((fo = fopen(argv[3], "wb")) != NULL)    {
               while ((ch = decrypt(fi)) != EOF)    {
                   /* --- test for run length counter --- */
                   if (ch & 0x80)
                       runct = ch & 0x7f;
                   else    {
                       if (runct)
                           /* --- run count: dup the byte -- */
                           while (--runct)
                               fputc(ch, fo);
                       fputc(ch, fo);
                   }
               }
               fclose(fo);
           }
           fclose(fi);
       }
       if (cipher)
           free(cipher);
       if (key)
           free(key);
   }
}

/* ------ decryption function: returns decrypted byte ----- */
static char decrypt(FILE *fi)
{
   char ch = EOF;
   if (clen == 0)    {
       /* ---- read a block of encrypted bytes ----- */
       clen = fread(cipher, 1, keylen, fi);
       coff = 0;
   }
   if (clen > 0)    {
       /* --- decrypt the next byte in the input block --- */
       ch = *(cipher+coff) ^ *(key+coff);
       coff++;
       --clen;
   }
   return ch;
}
