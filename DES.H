/* -------------- des.h ---------------- */
/* Header file for Data Encryption Standard algorithms  */

/* -------------- prototypes ------------------- */
VOID initkey(char *key);
VOID encrypt(char *blk);
VOID decrypt(char *blk);
VOID setparity(CHAR *key);

/* ----------- tables ------------ */
extern UCHAR Pmask[];
extern UCHAR IPtbl[];
extern UCHAR Etbl[];
extern UCHAR Ptbl[];
extern UCHAR stbl[8][4][16];
extern UCHAR PC1tbl[];
extern UCHAR PC2tbl[];
extern UCHAR ex6[8][2][4];
