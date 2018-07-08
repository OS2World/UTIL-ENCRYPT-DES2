# IBM Developer's Workframe/2 Make File Creation run at 22:41:52 on 03/15/93

# Make File Creation run in directory:
#   F:\DES;

.SUFFIXES:

.SUFFIXES: .c

tstdes.exe:  \
  DES.OBJ \
  TABLES.OBJ \
  tstdes.OBJ \
  TSTDES.MAK
   @REM @<<TSTDES.@0
     /CO /NOL /PM:VIO +
     DES.OBJ +
     TABLES.OBJ +
     tstdes.OBJ
     tstdes.exe
     
     
     ;
<<
   LINK386.EXE @TSTDES.@0

{.}.c.obj:
   ICC.EXE /Q /Ti /C .\$*.c

!include TSTDES.DEP
