@ECHO OFF
cl.exe /nologo /c /0d /MT /W0 /EHsc- /DUNICODE /DBOF /guard:cf- /GL- /GS- /Tc dataexfil-https-chunkbin-bof.c
move /y dataexfil-https-chunkbin-bof.obj dataexfil-https-chunkbin-bof.o
dumpbin /disasm dataexfil-https-chunkbin-bof.o > dataexfil-https-chunkbin-bof.disasm
