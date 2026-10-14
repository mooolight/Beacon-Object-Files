@ECHO OFF
cl.exe /nologo /c /0d /MT /W0 /EHsc- /DUNICODE /DBOF /guard:cf- /GL- /GS- /Tp .\WinShutdown-WMI-BOF.cpp
move /y WinShutdown-WMI-BOF.obj .\WinShutdown-WMI-BOF.o
dumpbin /disasm .\WinShutdown-WMI-BOF.o > .\WinShutdown-WMI-BOF.disasm
