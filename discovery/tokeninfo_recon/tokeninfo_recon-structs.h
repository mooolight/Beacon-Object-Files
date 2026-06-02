#include <windows.h>
#include <process.h>
#include <winternl.h>
#include <stdio.h>
#include <Aclapi.h>
#include <stdlib.h>
#include <tlhelp32.h>
#include <stddef.h>
#include <sddl.h>
#include <processsnapshot.h>
#include <windef.h>

#define RETVAL_TAG 0xAABBCCDD
