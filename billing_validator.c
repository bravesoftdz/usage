#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <openssl/sha.h>

#include "zip.h"
#include "billing_validator.h"
#include "base64.h"

//bool is_zip_corrupt(const char *);
//static void build_usage_from_zip(const char *zip_n);

struct zip *zip_open(const char *, int, int *);

static void 
help(const char *pg_name) {
    printf("usage: %s zip_file_name\n", pg_name);
    exit(1);
}

struct zip_file * 
zip_fseek(struct zip *za, struct zip_file *zipf, const char *fname) {
    zip_fclose(zipf);
    return zip_fopen(za, fname, ZIP_FL_UNCHANGED);
}

int
sha256_stream(const char *stream, unsigned char out[33]) {

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    int len = strlen(stream);

    SHA256_Update(&sha256, stream, strlen(stream));
    SHA256_Final(hash, &sha256);

    int i = 0;
    for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        //sprintf(out + (i*2), "%02x", hash[i]);
        out[i] = hash[i];
    }

    out[SHA256_DIGEST_LENGTH] = 0;

    return 0;
}

int
sha256(struct zip *za, const char *file, struct zip_file *zfile, unsigned char out[33]) {

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    struct zip_stat sb;
    
    if (zip_stat(za, file, 0, &sb)) {
        fprintf(stderr, "did not get the file '%s' stat, err: %s \n", file, zip_strerror(za));
        return 1;
    }

    char *buff = malloc(sb.size + 1);
    if (!buff) {
        fprintf(stderr, "mem allocation failed: %s\n", strerror(errno));
        return 1;
    }
    
    buff[sb.size] = 0;
    if (zip_fread(zfile, buff, sb.size) != sb.size) {
        fprintf(stderr, "reading the file '%s' failed\n", file);
        return 1;
    } 

    SHA256_Update(&sha256, buff, strlen(buff));
    SHA256_Final(hash, &sha256);

    int i = 0;
    for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        //sprintf(out + (i*2), "%02x", hash[i]);
        out[i] = hash[i];
    }

    out[SHA256_DIGEST_LENGTH] = 0;

    free(buff);
    return 0;
}

void
load_usage(usage_sum_t *usage) {
    return;
} 


char *
read_zip_file (struct zip *za, const char *file, struct zip_file *zfile) {

    struct zip_stat sb;
    
    if (zip_stat(za, file, 0, &sb)) {
        fprintf(stderr, "did not get the file '%s' stat, err: %s \n", file, zip_strerror(za));
        return NULL;
    }

    char *buff = malloc(sb.size + 1);
    if (!buff) {
        fprintf(stderr, "mem allocation failed: %s\n", strerror(errno));
        return NULL;
    }
    
    buff[sb.size] = 0;
    if (zip_fread(zfile, buff, sb.size) != sb.size) {
        fprintf(stderr, "reading the file '%s' failed\n", file);
        return NULL;
    } 

    return buff;
}

int main(int argc, char *argv[]) {
    
    if (argc != 2) {
        help(argv[0]);   
    }

    const char *zip_name = argv[1];
    struct zip *zip_arch;
    int err;
    char err_buf[100];
    usage_sum_t *usage;
    usage = (usage_sum_t *)malloc(sizeof(usage_sum_t));

    char *hash_xml_b64;
    char *manifest_hash_in_file;
    char *hash_manifest_b64_1;
    char *hash_manifest_b64_2;
    char *sf_hash_in_file_1;
    char *sf_hash_in_file_2;

    //create the archive
    if ((zip_arch = zip_open(zip_name, 0, &err)) == NULL) {
        zip_error_to_str(err_buf, sizeof(err_buf), err, errno);
        fprintf(stderr, "%s: can't open zip archive '%s', %s\n", argv[0], zip_name, err_buf);
        goto error;
    }

    //feed the file names
    if ((usage->xml_name = zip_get_name(zip_arch, XML, 0)) == NULL) {
        fprintf(stderr, "err happend when getting the file XML, %s\n", zip_strerror(zip_arch));
        goto error;
    }
    
    if ((usage->manifest_name = zip_get_name(zip_arch, MANIFEST, 0)) == NULL) {
        fprintf(stderr, "err happend when getting the file MANIFEST, %s\n", zip_strerror(zip_arch));
        goto error;
    }
    
    if ((usage->rsa_name = zip_get_name(zip_arch, RSAA, 0)) == NULL) {
        fprintf(stderr, "err happend when getting the file RSA, %s\n", zip_strerror(zip_arch));
        goto error;
    }
    
    if ((usage->sf_name = zip_get_name(zip_arch, SF, 0)) == NULL) {
        fprintf(stderr, "err happend when getting the file SF, %s\n", zip_strerror(zip_arch));
        goto error;
    }
    
    if (!strstr(usage->xml_name, ".xml") || 
        !strstr(usage->manifest_name, ".MF") || 
        !strstr(usage->rsa_name, ".RSA") || 
        !strstr(usage->sf_name, ".SF")) {
        fprintf(stderr, "archive index is messed up, someone touched!!!\n");
        goto error;
    }
     
    //open files
    if ((usage->xml = zip_fopen(zip_arch, usage->xml_name, ZIP_FL_UNCHANGED)) == NULL) {
        fprintf(stderr, "err happend when openning the xml file, %s\n", zip_strerror(zip_arch));
        goto error;
    }

    if ((usage->manifest = zip_fopen(zip_arch, usage->manifest_name, ZIP_FL_UNCHANGED)) == NULL) {
        fprintf(stderr, "err happend when openning the manifest file, %s\n", zip_strerror(zip_arch));
        goto error;
    }

    if ((usage->rsa = zip_fopen(zip_arch, usage->rsa_name, ZIP_FL_UNCHANGED)) == NULL) {
        fprintf(stderr, "err happend when openning the rsa file, %s\n", zip_strerror(zip_arch));
        goto error;
    }

    if ((usage->sf = zip_fopen(zip_arch, usage->sf_name, ZIP_FL_UNCHANGED)) == NULL) {
        fprintf(stderr, "err happend when openning the sf file, %s\n", zip_strerror(zip_arch));
        goto error;
    }

    //cacluate the hash
    unsigned char hash_temp[33];

    if (sha256(zip_arch, usage->xml_name, usage->xml, hash_temp)) {
        fprintf(stderr, "can not hash the xml file\n");
        goto error;
    }

    //encode the hash
    //char *hash_xml_64 = base64_encode(hash_temp);
    Base64Encode(hash_temp, &hash_xml_b64);

    //read the original value from manifest
    char *buff_temp = read_zip_file(zip_arch, usage->manifest_name, usage->manifest);

    if (buff_temp == NULL) {
        fprintf(stderr, "can not read the manifest file into buffer\n");
        goto error;
    }
    
    char *temp;
    temp = strtok(buff_temp, "\n");    
    while (!(strstr(temp, "Digest"))) {
        temp = strtok(NULL, "\n");
    }
    
    temp = strtok(temp, " ");    
    manifest_hash_in_file = strtok(NULL, " ");

    //compare the hash in xml with the one inside manifest
    if (!(strcmp(manifest_hash_in_file, hash_xml_b64))) {
        fprintf(stderr, "the XML file or the manifest file has been modified!!!\n");
        goto error;
    }
    
    //get the 1st hash inside manifest
    if (!(usage->manifest = zip_fseek(zip_arch, usage->manifest, usage->manifest_name))) {
        fprintf(stderr, "err happend when openning the manifest file, %s\n", zip_strerror(zip_arch));
        goto error;
    }

    if (sha256(zip_arch, usage->manifest_name, usage->manifest, hash_temp)) {
        fprintf(stderr, "can not hash the manifiest file\n");
        goto error;
    }

    Base64Encode(hash_temp, &hash_manifest_b64_1);

    //get the 2nd hash inside manifest
    if (!(usage->manifest = zip_fseek(zip_arch, usage->manifest, usage->manifest_name))) {
        fprintf(stderr, "err happend when openning the manifest file, %s\n", zip_strerror(zip_arch));
        goto error;
    }
    
    buff_temp = read_zip_file(zip_arch, usage->manifest_name, usage->manifest);
    if (buff_temp == NULL) {
        fprintf(stderr, "can not read the manifest file into buffer\n");
        goto error;
    }
    
    temp = strstr(buff_temp, "Name"); 

    if (sha256_stream(temp, hash_temp)) {
        fprintf(stderr, "can not hash the manifiest file\n");
        goto error;
    }

    Base64Encode(hash_temp, &hash_manifest_b64_2);

    //read the original value from sf file, first one
    buff_temp = read_zip_file(zip_arch, usage->sf_name, usage->sf);

    if (buff_temp == NULL) {
        fprintf(stderr, "can not read the manifest file into buffer\n");
        goto error;
    }
    
    temp = strtok(buff_temp, "\n");    
    while (!(strstr(temp, "SHA256-Digest-Manifest:"))) {
        temp = strtok(NULL, "\n");
    }
    temp = strtok(temp, " ");
    sf_hash_in_file_1 = strtok(NULL, " ");


    //read the original value from sf file, 2nd one
    if (!(usage->sf = zip_fseek(zip_arch, usage->sf, usage->sf_name))) {
        fprintf(stderr, "err happend when openning the sf file, %s\n", zip_strerror(zip_arch));
        goto error;
    }

    buff_temp = read_zip_file(zip_arch, usage->sf_name, usage->sf);

    if (buff_temp == NULL) {
        fprintf(stderr, "can not read the manifest file into buffer\n");
        goto error;
    }
    temp = strtok(buff_temp, "\n");    
    while (!(strstr(temp, "SHA256-Digest:"))) {
        temp = strtok(NULL, "\n");
    }
    temp = strtok(temp, " ");
    sf_hash_in_file_2 = strtok(NULL, " ");


    //compare the hash calculated by manifest with the value in sf
    if (!(strcmp(hash_manifest_b64_1, sf_hash_in_file_1)) || 
        !(strcmp(hash_manifest_b64_2, sf_hash_in_file_2))) {
        fprintf(stderr, "the manifest file or the sf file has been modified!!!\n");
        goto error;
    }

    //get here, all good
    printf("everything is untouched, great!!!\n");

    if (buff_temp)
        free(buff_temp);
    if (usage->xml)
        zip_fclose(usage->xml);
    if (usage->manifest)
        zip_fclose(usage->manifest);
    if (usage->rsa)
        zip_fclose(usage->rsa);
    if (usage->sf)
        zip_fclose(usage->sf);
    if (zip_arch) 
        zip_discard(zip_arch);

    return 0;

error:

    if (buff_temp)
        free(buff_temp);
    if (usage->xml)
        zip_fclose(usage->xml);
    if (usage->manifest)
        zip_fclose(usage->manifest);
    if (usage->rsa)
        zip_fclose(usage->rsa);
    if (usage->sf)
        zip_fclose(usage->sf);
    if (zip_arch) 
        zip_discard(zip_arch);
    
    fprintf(stderr, "error happed\n");
    return 1;
}
