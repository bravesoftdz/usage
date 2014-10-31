#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <stdio.h>
#include <math.h>

#include "base64.h"

char *base64_encode( const char *str ) {

    BIO *base64_filter = BIO_new(BIO_f_base64());
    BIO_set_flags(base64_filter, BIO_FLAGS_BASE64_NO_NL);

    BIO *bio = BIO_new(BIO_s_mem());
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    bio = BIO_push(base64_filter, bio);

    BIO_write(bio, str, strlen(str));

    BIO_flush(bio);

    char *new_data;

    long bytes_written = BIO_get_mem_data(bio, &new_data);

    printf("%x\n", new_data);

    BIO_free_all(bio);

    return new_data;
}

int 
Base64Encode(const char *message, char **buffer) {
    BIO *bio, *b64;
    FILE* stream;
    int encodedSize = 4*ceil((double)32/3);
    *buffer = (char *)malloc(encodedSize+1);
          
    stream = fmemopen(*buffer, encodedSize+1, "w");
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_fp(stream, BIO_NOCLOSE);
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, message, 32);
    BIO_flush(bio);
    BIO_free_all(bio);
    fclose(stream);
                             
    return (0);
}



char *base64_decode(const char *str) {

    BIO *bio, *base64_filter, *bio_out;
    char inbuf[512];
    int inlen;
    base64_filter = BIO_new(BIO_f_base64());
    BIO_set_flags(base64_filter, BIO_FLAGS_BASE64_NO_NL);

    bio = BIO_new_mem_buf((void*)str, strlen(str));

    bio = BIO_push(base64_filter, bio);

    bio_out = BIO_new(BIO_s_mem());

    while((inlen = BIO_read(bio, inbuf, 512)) > 0 ) {
        BIO_write(bio_out, inbuf, inlen);
    }

    BIO_flush(bio_out);

    char *new_data;
    long bytes_written = BIO_get_mem_data(bio_out, &new_data);

    BIO_free_all(bio);
    BIO_free_all(bio_out);

    return new_data;
}


const int 
calcDecodeLength(const char* b64input) { //Calculates the length of a decoded base64 strin
    int len = strlen(b64input);
    int padding = 0;
         
    if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
        padding = 2;
    else if (b64input[len-1] == '=') //last char is =
        padding = 1;
             
    return (int)len*0.75 - padding;
}
 
int 
Base64Decode(char* b64message, char** buffer) { //Decodes a base64 encoded string
    BIO *bio, *b64;
    int decodeLen = calcDecodeLength(b64message), len = 0;
    *buffer = (char*)malloc(decodeLen+1);
    FILE* stream = fmemopen(b64message, strlen(b64message), "r");
             
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_fp(stream, BIO_NOCLOSE);
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Do not use newlines to flush buffer
    len = BIO_read(bio, *buffer, strlen(b64message));
    (*buffer)[len] = '\0';
                             
    BIO_free_all(bio);
    fclose(stream);
                                  
    return(0);
}
