cl.exe /nologo /c /0d /MT /W0 /EHsc- /DUNICODE /DBOF /guard:cf- /GL- /GS- /Tc .\data-exfil\dataexfil-https-chunkbin-bof.c
move /y dataexfil-https-chunkbin-bof.obj .\data-exfil\dataexfil-https-chunkbin-bof.o
dumpbin /disasm .\data-exfil\dataexfil-https-chunkbin-bof.o > .\data-exfil\dataexfil-https-chunkbin-bof.disasm
