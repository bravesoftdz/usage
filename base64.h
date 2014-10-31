#ifndef __BASE64_H__
#define __BASE64_H__

#include <openssl/bio.h>
#include <openssl/evp.h>

char *base64_encode(const char *);
char *base64_decode(const char *);
int Base64Encode(const char*, char**);
int Base64Decode(char*, char**);

#endif
