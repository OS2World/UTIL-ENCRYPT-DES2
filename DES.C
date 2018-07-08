/* ---------------------- des.c --------------------------- */
/* Functions and tables for DES encryption and decryption
 */

#define INCL_BASE
#include <os2.h>
#include <stdio.h>
#include <string.h>
#include "des.h"

/* -------- 48-bit key permutation ------- */
struct ks
   {
   CHAR ki[6];
   };

/* ------- two halves of a 64-bit data block ------- */
struct LR
   {
   LONG L;
   LONG R;
   };

static struct ks keys[16];

VOID rotate(UCHAR *c, SHORT n);
SHORT fourbits(struct ks, SHORT s);
SHORT sixbits(struct ks, SHORT s);
VOID inverse_permute(LONG *op,LONG *ip,LONG *tbl,SHORT n);
VOID permute(LONG *op, LONG *ip, LONG *tbl, SHORT n);
LONG f(LONG blk, struct ks ky);
struct ks KS(SHORT n, CHAR *key);
VOID swapbyte(LONG *l);


SHORT EXPENTRY EncryptData(CHAR *key, CHAR *data, SHORT length)
{
UCHAR lkey[9], block[8], *ptr ;
SHORT x ;

memset(lkey, 0, 9) ;
strcpy(lkey, key) ;
if(strlen(lkey) > 8)
    lkey[8] = 0 ;

setparity(lkey);
initkey(lkey);
ptr = data ;
   for(x = 0 ; x <= length/8 ; x++)
      {
      memcpy(block, ptr, 8) ;
      encrypt(block);
      memcpy(ptr, block, 8) ;
      ptr+= 8 ;
      }
data[length] = 0 ;
}


SHORT EXPENTRY DecryptData(CHAR *key, CHAR *data, SHORT length)
{
UCHAR lkey[9], block[8], *ptr ;
SHORT x ;

memset(lkey, 0, 9) ;
strcpy(lkey, key) ;
if(strlen(lkey) > 8)
    lkey[8] = 0 ;

setparity(lkey);
initkey(lkey);
ptr = data ;
   for(x = 0 ; x <= length/8 ; x++)
      {
      memcpy(block, ptr, 8) ;
      decrypt(block);
      memcpy(ptr, block, 8) ;
      ptr+= 8 ;
      }
data[length] = 0 ;
}


/* ----------- initialize the key -------------- */
VOID initkey(CHAR *key)
{
SHORT i;
for (i = 0; i < 16; i++)
   keys[i] = KS(i, key);
}

/* ----------- encrypt an 8-byte block ------------ */
VOID encrypt(CHAR *blk)
{
struct LR ip, op;
LONG temp;
SHORT n;

memcpy(&ip, blk, sizeof(struct LR));
/* -------- initial permuation -------- */
permute(&op.L, &ip.L, (LONG *)IPtbl, 64);
swapbyte(&op.L);
swapbyte(&op.R);
/* ------ swap and key iterations ----- */
for (n = 0; n < 16; n++)
   {
   temp = op.R;
   op.R = op.L ^ f(op.R, keys[n]);
   op.L = temp;
   }
ip.R = op.L;
ip.L = op.R;
swapbyte(&ip.L);
swapbyte(&ip.R);
/* ----- inverse initial permutation ---- */
inverse_permute(&op.L, &ip.L,
    (LONG *)IPtbl, 64);
memcpy(blk, &op, sizeof(struct LR));
}

/* ----------- decrypt an 8-byte block ------------ */
VOID decrypt(CHAR *blk)
{
struct LR ip, op;
LONG temp;
SHORT n;

memcpy(&ip, blk, sizeof(struct LR));
/* -------- initial permuation -------- */
permute(&op.L, &ip.L, (LONG *)IPtbl, 64);
swapbyte(&op.L);
swapbyte(&op.R);
ip.R = op.L;
ip.L = op.R;
/* ------ swap and key iterations ----- */
for (n = 15; n >= 0; --n)
   {
   temp = ip.L;
   ip.L = ip.R ^ f(ip.L, keys[n]);
   ip.R = temp;
   }
swapbyte(&ip.L);
swapbyte(&ip.R);
/* ----- inverse initial permuation ---- */
inverse_permute(&op.L, &ip.L,
    (LONG *)IPtbl, 64);
memcpy(blk, &op, sizeof(struct LR));
}

/* ------- inverse permute a 64-bit string ------- */
VOID inverse_permute(LONG *op,LONG *ip,LONG *tbl,SHORT n)
{
SHORT i;
LONG *pt = (LONG *)Pmask;

*op = *(op+1) = 0;
for (i = 0; i < n; i++)
   {
   if ((*ip & *pt) || (*(ip+1) & *(pt+1)))
      {
      *op |= *tbl;
      *(op+1) |= *(tbl+1);
      }
   tbl += 2;
   pt += 2;
   }
}

/* ------- permute a 64-bit string ------- */
VOID permute(LONG *op, LONG *ip, LONG *tbl, SHORT n)
{
SHORT i;
LONG *pt = (LONG *)Pmask;

*op = *(op+1) = 0;
for (i = 0; i < n; i++)
   {
   if ((*ip & *tbl) || (*(ip+1) & *(tbl+1)))
      {
      *op |= *pt;
      *(op+1) |= *(pt+1);
      }
   tbl += 2;
   pt += 2;
   }
}

/* ----- Key dependent computation function f(R,K) ----- */
LONG f(LONG blk, struct ks key)
{
struct LR ir;
struct LR or;
SHORT i;

union
   {
   struct LR f;
   struct ks kn;
   } tr = {0,0}, kr = {0,0};

ir.L = blk;
ir.R = 0;

kr.kn = key;

swapbyte(&ir.L);
swapbyte(&ir.R);

permute(&tr.f.L, &ir.L, (LONG *)Etbl, 48);

tr.f.L ^= kr.f.L;
tr.f.R ^= kr.f.R;

/*   the DES S function: ir.L = S(tr.kn);  */
ir.L = 0;
for (i = 0; i < 8; i++)
   {
   LONG four = fourbits(tr.kn, i);
   ir.L |= four << ((7-i) * 4);
   }
swapbyte(&ir.L);

ir.R = or.R = 0;
permute(&or.L, &ir.L, (LONG *)Ptbl, 32);

swapbyte(&or.L);
swapbyte(&or.R);

return or.L;
}

/* ------- extract a 4-bit stream from the block/key ------- */
SHORT fourbits(struct ks k, SHORT s)
{
SHORT i, row, col ;

i = sixbits(k, s);
row = ((i >> 4) & 2) | (i & 1);
col = (i >> 1) & 0xf;
return stbl[s][row][col];
}

/* ---- extract 6-bit stream fr pos s of the  block/key ---- */
SHORT sixbits(struct ks k, SHORT s)
{
SHORT op = 0;
SHORT n = (s);
SHORT i;
for (i = 0; i < 2; i++)
   {
   SHORT off = ex6[n][i][0];
   UCHAR c = k.ki[off];
   c >>= ex6[n][i][1];
   c <<= ex6[n][i][2];
   c &=  ex6[n][i][3];
   op |= c;
   }
return op;
}

/* ---------- DES Key Schedule (KS) function ----------- */
struct ks KS(SHORT n, CHAR *key)
{
 UCHAR cd[8];
 SHORT its[] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};
union
   {
   struct ks kn;
   struct LR filler;
   } result;

if (n == 0)
    permute((LONG *)cd, (LONG *) key, (LONG *)PC1tbl, 64);

rotate(cd, its[n]);
rotate(cd+4, its[n]);

permute(&result.filler.L, (LONG *)cd, (LONG *)PC2tbl, 48);
return result.kn;
}

/* rotate a 4-byte string n (1 or 2) positions to the left */
VOID rotate(UCHAR *c, SHORT n)
{
SHORT i;
USHORT j, k;

k = ((*c) & 255) >> (8 - n);
for (i = 3; i >= 0; --i)
   {
   j = ((*(c+i) << n) + k);
   k = (j >> 8) & 255;
   *(c+i) = j & 255;
   }
if (n == 2)
   *(c+3) = (*(c+3) & 0xc0) | ((*(c+3) << 4) & 0x30);
else
   *(c+3) = (*(c+3) & 0xe0) | ((*(c+3) << 4) & 0x10);
}

/* -------- swap bytes in a LONG integer ---------- */
VOID swapbyte(LONG *l)
{
CHAR *cp = (CHAR *) l;
CHAR t = *(cp+3);

*(cp+3) = *cp;
*cp = t;
t = *(cp+2);
*(cp+2) = *(cp+1);
*(cp+1) = t;
}

/* -------- make a CHARacter odd parity ---------- */
UCHAR oddparity(UCHAR s)
{
UCHAR c = s | 0x80;
while (s)
   {
   if (s & 1)
      c ^= 0x80;
   s = (s >> 1) & 0x7f;
   }
return c;
}

/* ------ make a key odd parity ------- */
VOID setparity(CHAR *key)
{
SHORT i;
for (i = 0; i < 8; i++)
   *(key+i) = oddparity(*(key+i));
}
