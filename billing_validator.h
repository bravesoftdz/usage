
#ifndef __BILLING_VALIDATOR_H__
#define __BILLING_VALIDATOR_H__

#include <stdbool.h>

#define MANIFEST 0
#define SF 1
#define RSAA 2
#define XML 3

typedef struct usage_sum {
    const char *zip_n;
    const char *cwd;
    const char *manifest_name;
    const char *xml_name;
    const char *sf_name;
    const char *rsa_name;
    struct zip_file *xml;
    struct zip_file *manifest;
    struct zip_file *sf;
    struct zip_file *rsa;
} usage_sum_t;

//bool is_zip_corrupt(const char *zip_n);

#endif
