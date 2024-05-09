#include <memory.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>

#include "openssl/evp.h"
#include "openssl/ec.h"
#include "openssl/ecdsa.h"
#include "openssl/err.h"
#include "openssl/core_dispatch.h"
#include "openssl/core_names.h"

/* Get an architecture specific most precise clock source with the lowest
 * overhead. Should be executed at the start of the measurement period
 * (because of barriers against speculative execution
 */
uint64_t get_time_before() {
    uint64_t time_before = 0;
#if defined( __s390x__ )
    /* The 64 bit TOD (time-of-day) value is running at 4096.000MHz, but
     * on some machines not all low bits are updated (the effective frequency
     * remains though)
     */

    /* use STCKE as it has lower overhead,
     * see http://publibz.boulder.ibm.com/epubs/pdf/dz9zr007.pdf
     */
    //asm volatile (
    //    "stck    %0": "=Q" (time_before) :: "memory", "cc");

    uint8_t clk[16];
    asm volatile (
          "stcke %0" : "=Q" (clk) :: "memory", "cc");
    /* since s390x is big-endian we can just do a byte-by-byte copy,
     * First byte is the epoch number (143 year cycle) while the following
     * 8 bytes are the same as returned by STCK */
    time_before = *(uint64_t *)(clk + 1);
#elif defined( __PPC64__ )
    asm volatile (
        "mftb    %0": "=r" (time_before) :: "memory", "cc");
#elif defined( __aarch64__ )
    asm volatile (
        "mrs %0, cntvct_el0": "=r" (time_before) :: "memory", "cc");
#elif defined( __x86_64__ ) || defined( __i386__ )
    uint32_t time_before_high = 0, time_before_low = 0;
    asm volatile (
        "CPUID\n\t"
        "RDTSC\n\t"
        "mov %%edx, %0\n\t"
        "mov %%eax, %1\n\t" : "=r" (time_before_high),
        "=r" (time_before_low)::
        "%rax", "%rbx", "%rcx", "%rdx");
    time_before = (uint64_t)time_before_high<<32 | time_before_low;
#else
#error Unsupported architecture
#endif /* ifdef __s390x__ */
    return time_before;
}

/* Get an architecture specific most precise clock source with the lowest
 * overhead. Should be executed at the end of the measurement period
 * (because of barriers against speculative execution
 */
uint64_t get_time_after() {
    uint64_t time_after = 0;
#if defined( __s390x__ )
    /* The 64 bit TOD (time-of-day) value is running at 4096.000MHz, but
     * on some machines not all low bits are updated (the effective frequency
     * remains though)
     */

    /* use STCKE as it has lower overhead,
     * see http://publibz.boulder.ibm.com/epubs/pdf/dz9zr007.pdf
     */
    //asm volatile (
    //    "stck    %0": "=Q" (time_before) :: "memory", "cc");

    uint8_t clk[16];
    asm volatile (
          "stcke %0" : "=Q" (clk) :: "memory", "cc");
    /* since s390x is big-endian we can just do a byte-by-byte copy,
     * First byte is the epoch number (143 year cycle) while the following
     * 8 bytes are the same as returned by STCK */
    time_after = *(uint64_t *)(clk + 1);
#elif defined( __PPC64__ )
    /* Note: mftb can be used with a single instruction on ppc64, for ppc32
     * it's necessary to read upper and lower 32bits of the values in two
     * separate calls and verify that we didn't do that during low value
     * overflow
     */
    asm volatile (
        "mftb    %0": "=r" (time_after) :: "memory", "cc");
#elif defined( __aarch64__ )
    asm volatile (
        "mrs %0, cntvct_el0": "=r" (time_after) :: "memory", "cc");
#elif defined( __x86_64__ ) || defined( __i386__ )
    uint32_t time_after_high = 0, time_after_low = 0;
    asm volatile (
        "RDTSCP\n\t"
        "mov %%edx, %0\n\t"
        "mov %%eax, %1\n\t"
        "CPUID\n\t": "=r" (time_after_high),
        "=r" (time_after_low)::
        "%rax", "%rbx", "%rcx", "%rdx");
    time_after = (uint64_t)time_after_high<<32 | time_after_low;
#else
#error Unsupported architecture
#endif /* ifdef __s390x__ */
    return time_after;
}

void help(char *name) {
    printf("Usage: %s -i file -o file -t file -k file [-h]\n", name);
    printf("\n");
    printf(" -i file    File with data to sign\n");
    printf(" -o file    File to write the signatures \n");
    printf(" -t file    File to write the time to sign the hashes\n");
    printf(" -k file    File with the private key in PEM format\n");
    printf(" -s num     Size of each block of data to sign\n");
    printf(" -h         This message\n");
}

int main(int argc, char *argv[]) {
    FILE *fp;
    char *key_file_name = NULL, *in_file_name = NULL, *out_file_name = NULL, *time_file_name = NULL;
    int in_fd = -1, out_fd = -1, time_fd = -1;
    int opt;
    int result = 1, r_ret;
    size_t data_size = 32, sig_len = 0, sig_len_max = 512;
    unsigned char *data = NULL, *sig = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    unsigned int one = 1;
    OSSL_PARAM deterministic_set[] = {
        OSSL_PARAM_uint(OSSL_SIGNATURE_PARAM_NONCE_TYPE, &one),
        OSSL_PARAM_END
    };
    uint64_t time_before, time_after, time_diff;

    fprintf(stderr, "Starting program %s...\n", argv[0]);
    fprintf(stderr, "%s\n", OpenSSL_version(0));
    fprintf(stderr, "%s\n", OpenSSL_version(2));

    while ((opt = getopt(argc, argv, "i:o:t:k:s:h")) != -1 ) {
        switch (opt) {
            case 'i':
                in_file_name = optarg;
                break;
            case 'o':
                out_file_name = optarg;
                break;
            case 't':
                time_file_name = optarg;
                break;
            case 'k':
                key_file_name = optarg;
                break;
            case 's':
                sscanf(optarg, "%zi", &data_size);
                break;
            case 'h':
                help(argv[0]);
                exit(0);
                break;
            default:
                fprintf(stderr, "Unknown option: %c\n", opt);
                help(argv[0]);
                exit(1);
                break;
        }
    }

    if (!in_file_name || !out_file_name || !time_file_name || !key_file_name) {
        fprintf(stderr, "Missing parameters!\n");
        help(argv[0]);
        exit(1);
    }

    in_fd = open(in_file_name, O_RDONLY);
    if (in_fd == -1) {
        fprintf(stderr, "can't open input file %s\n", in_file_name);
        goto err;
    }

    out_fd = open(out_file_name, O_WRONLY|O_TRUNC|O_CREAT, 0666);
    if (out_fd == -1) {
        fprintf(stderr, "can't open output file %s\n", out_file_name);
        goto err;
    }

    time_fd = open(time_file_name, O_WRONLY|O_TRUNC|O_CREAT, 0666);
    if (time_fd == -1) {
        fprintf(stderr, "can't open output file %s\n", time_file_name);
        goto err;
    }

    fp = fopen(key_file_name, "r");
    if (!fp) {
        fprintf(stderr, "Can't open key file %s\n", key_file_name);
        goto err;
    }

    data = malloc(data_size);
    if (!data){
        fprintf(stderr, "Can't malloc enough space for data size: %d\n", data_size);
        goto err;
    }

    if ((pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL)) == NULL){
        fprintf(stderr, "Can't read priv key \n");
        goto err;
    }

    /* Allocate memory for the signature based on size in slen */
    sig = (unsigned char*)malloc(sig_len_max);
    if(!sig){
        fprintf(stderr, "Can't malloc enough space for signature size: %d\n", sig_len_max);
        goto err;
    }

    /* Create the Message Digest Context */
    if(!(mdctx = EVP_MD_CTX_create())){
        fprintf(stderr, "EVP_MD_CTX_create\n");
        goto err;
    }

    while ((r_ret = read(in_fd, data, data_size)) > 0) {
        if (r_ret != data_size) {
            fprintf(stderr, "read less data than expected (truncated file?)\n");
            fprintf(stderr, "read %d bytes instead of %d\n", r_ret, data_size);
            goto err;
        }

        sig_len = sig_len_max;

        // time_before = get_time_before();

        /* Initialise the DigestSign operation - SHA-256 has been selected as the message digest function in this example */
        if(EVP_DigestSignInit(mdctx, &pctx, EVP_sha256(), NULL, pkey) == 0){
            fprintf(stderr, "EVP_DigestSignInit\n");
            goto err;
        }

        /* Set deterministic flag */
        if(EVP_PKEY_CTX_set_params(pctx, &deterministic_set) == 0){
            fprintf(stderr, "EVP_PKEY_CTX_set_params\n");
            goto err;
        }

        /* Call update with the message */
        if(EVP_DigestSignUpdate(mdctx, data, data_size) == 0){
            fprintf(stderr, "EVP_DigestSignUpdate\n");
            goto err;
        }

        // time_after = get_time_after();
        time_before = get_time_before();

        /* Obtain the signature */
        r_ret = EVP_DigestSignFinal(mdctx, sig, &sig_len);
        if(r_ret == 0){
            fprintf(stderr, "EVP_DigestSignFinal\n");
            goto err;
        }

        time_after = get_time_after();

        time_diff = time_after - time_before;

        r_ret = write(time_fd, &time_diff, sizeof(time_diff));
        if (r_ret <= 0) {
            fprintf(stderr, "Write error on times\n");
            goto err;
        }

        r_ret = write(out_fd, sig, sig_len);
        if (r_ret <= 0) {
            fprintf(stderr, "Write error on signatures\n");
            goto err;
        }
    }

    result = 0;
    fprintf(stderr, "finished\n");
    goto out;

    err:
    result = 1;
    fprintf(stderr, "failed!\n");
    ERR_print_errors_fp(stderr);

    out:

    if (data)
        free(data);
    if (sig)
        free(sig);
    if (in_fd >= 0)
        close(in_fd);
    if (out_fd >= 0)
        close(out_fd);
    if (time_fd >= 0)
        close(time_fd);
    if (fp)
        fclose(fp);
    if (pkey)
        EVP_PKEY_free(pkey);
    if (mdctx){
        EVP_MD_CTX_free(mdctx);
    }

    return result;

}