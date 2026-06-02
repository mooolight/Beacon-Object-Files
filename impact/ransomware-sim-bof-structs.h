#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>

#define AES_BLOCK_SIZE 16
#define IN_CHUNK_SIZE (AES_BLOCK_SIZE * 10)
#define OUT_CHUNK_SIZE (IN_CHUNK_SIZE * 2)