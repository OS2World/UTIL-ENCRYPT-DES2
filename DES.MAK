# IBM Developer's Workframe/2 Make File Creation run at 22:20:55 on 03/15/93

# Make File Creation run in directory:
#   F:\DES;

.SUFFIXES:

.SUFFIXES: .c

DES.DLL:  \
  DES.OBJ \
  TABLES.OBJ \
  DES.DEF \
  DES.MAK
   @REM @<<DES.@0
     /NOL /PM:VIO +
     DES.OBJ +
     TABLES.OBJ
     DES.DLL
     
     
     DES.DEF;
<<
   LINK386.EXE @DES.@0
  IMPLIB DES.LIB DES.DEF

{.}.c.obj:
   ICC.EXE /Q /Ge- /C .\$*.c

!include DES.DEP
