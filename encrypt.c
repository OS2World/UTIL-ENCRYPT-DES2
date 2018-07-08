/* ---------------------- encrypto.c ----------------------- */
/* Single key text file encryption
 * Usage: encrypto keyvalue infile outfile
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FALSE 0
#define TRUE !FALSE

static void charout(FILE *fo, char prev, int runct, int last);
static void encrypt(FILE *fo, char ch, int last);

static char *key = NULL;
static int keylen;
static char *cipher = NULL;
static int clen = 0;

void main(int argc, char *argv[])
{
   FILE *fi, *fo;
   char ch, prev = 0;
   int runct = 0;

   if (argc > 3)    {
       /* --- alloc memory for the key and cipher blocks --- */
       keylen = strlen(argv[1]);
       cipher = malloc(keylen+1);
       key = malloc(keylen+1);
       strcpy(key, argv[1]);

       if (cipher != NULL && key != NULL &&
               (fi = fopen(argv[2], "rb")) != NULL)        {
           if ((fo = fopen(argv[3], "wb")) != NULL)    {
               while ((ch = fgetc(fi)) != EOF)    {
                    /* ---- validate ASCII input ---- */
                   if (ch & 128)    {
                       fprintf(stderr, "%s is not ASCII",
                                   argv[2]);
                       fclose(fi);
                       fclose(fo);
                       remove(argv[3]);
                       free(cipher);
                       free(key);
                       exit(1);
                   }

                   /* --- test for duplicate bytes --- */
                   if (ch == prev && runct < 127)
                       runct++;
                   else    {
                       charout(fo, prev, runct, FALSE);
                       prev = ch;
                       runct = 0;
                   }
               }
               charout(fo, prev, runct, TRUE);
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

/* ------- send an encrypted byte to the output file ------ */
static void charout(FILE *fo, char prev, int runct, int last)
{
   if (runct)
       encrypt(fo, (runct+1) | 0x80, last);
   if (prev)
       encrypt(fo, prev, last);
}

/* ---------- encrypt a byte and write it ---------- */
static void encrypt(FILE *fo, char ch, int last)
{
   *(cipher+clen) = ch ^ *(key+clen);
   clen++;
   if (last || clen == keylen)    {
       /* ----- cipher buffer full or last buffer ----- */
       int i;
       for (i = 0; i < clen; i++)
           fputc(*(cipher+i), fo);
       clen = 0;
   }
}
