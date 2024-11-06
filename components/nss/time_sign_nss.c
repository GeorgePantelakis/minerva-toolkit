#include <memory.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>

#include "nss.h"
#include "pk11pub.h"
#include "sechash.h"
#include "pkcs11.h"
#include "prerror.h"

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
    printf(" -k file    Path to the NSS database with the private key\n");
    printf(" -s num     Size of each block of data to sign\n");
    printf(" -h         This message\n");
}

int main(int argc, char *argv[]) {
    char *db_name = NULL, *in_file_name = NULL, *out_file_name = NULL, *time_file_name = NULL;
    int in_fd = -1, out_fd = -1, time_fd = -1;
    int opt;
    int result = 1, r_ret;
    int sig_len = 0;
    size_t data_size = 32;
    uint64_t time_before, time_after, time_diff;
    unsigned char *data_buf = NULL, *sig_buf = NULL;
    SECItem sig = {siBuffer, sig_buf, sig_len};
    PK11SlotInfo *slot = NULL;
    SECKEYPrivateKey *privKey = NULL;
    CERTCertDBHandle *certDB = NULL;
    CERTCertificate *cert = NULL;
    SECKEYPrivateKeyList *privKeyList = NULL;
    SECKEYPrivateKeyListNode *node = NULL;

    fprintf(stderr, "Starting program %s...\n", argv[0]);

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
                db_name = optarg;
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

    if (!in_file_name || !out_file_name || !time_file_name || !db_name) {
        fprintf(stderr, "Missing parameters!\n");
        help(argv[0]);
        exit(1);
    }

    in_fd = open(in_file_name, O_RDONLY);
    if (in_fd == -1) {
        fprintf(stderr, "can't open input file %s.\n", in_file_name);
        goto err;
    }

    out_fd = open(out_file_name, O_WRONLY|O_TRUNC|O_CREAT, 0666);
    if (out_fd == -1) {
        fprintf(stderr, "can't open output file %s.\n", out_file_name);
        goto err;
    }

    time_fd = open(time_file_name, O_WRONLY|O_TRUNC|O_CREAT, 0666);
    if (time_fd == -1) {
        fprintf(stderr, "can't open output file %s.\n", time_file_name);
        goto err;
    }

    data_buf = malloc(data_size);
    if (!data_buf){
        fprintf(stderr, "Can't malloc enough space for data size: %d.\n", data_size);
        goto err;
    }

    if (NSS_Init(db_name) != SECSuccess){
        fprintf(stderr, "Can't open database %s\n", db_name);
        goto err;
    }

    if ((slot = PK11_GetInternalKeySlot()) == NULL){
        fprintf(stderr, "Can't get slot from db.\n");
        goto err;
    }

    privKeyList = PK11_ListPrivateKeysInSlot(slot);
    node = (SECKEYPrivateKeyListNode *)PR_LIST_HEAD(&privKeyList->list);
    privKey = node->key;

    if(privKey == NULL) {
        fprintf(stderr, "Can't read priv key.\n");
        goto err;
    }

    while ((r_ret = read(in_fd, data_buf, data_size)) > 0) {
        if (r_ret != data_size) {
            fprintf(stderr, "read less data than expected (truncated file?)\n");
            fprintf(stderr, "read %d bytes instead of %d.\n", r_ret, data_size);
            goto err;
        }

        time_before = get_time_before();

        if(SEC_SignData(&sig, data_buf, (int) data_size, privKey, SEC_OID_ANSIX962_ECDSA_SHA256_SIGNATURE) != SECSuccess){
            fprintf(stderr, "SEC_SignData.\n");
            goto err;
        }

        time_after = get_time_after();

        time_diff = time_after - time_before;

        r_ret = write(time_fd, &time_diff, sizeof(time_diff));
        if (r_ret <= 0) {
            fprintf(stderr, "Write error on times.\n");
            goto err;
        }

        r_ret = write(out_fd, sig.data, sig.len);
        if (r_ret <= 0) {
            fprintf(stderr, "Write error on signatures.\n");
            goto err;
        }
    }

    result = 0;
    fprintf(stderr, "finished.\n");
    goto out;

    err:
    result = 1;
    fprintf(stderr, "failed!\n");
    int error = PORT_GetError();
    (void) NSS_InitializePRErrorTable(); /* not necessary if you successfully call NSS_Init */
    fprintf(stderr, "Error (%d) -> %s\n", error,  PORT_ErrorToString(error));

    out:

    if (in_fd >= 0)
        close(in_fd);
    if (out_fd >= 0)
        close(out_fd);
    if (time_fd >= 0)
        close(time_fd);
    if (data_buf)
        free(data_buf);
    if (sig_buf)
        free(sig_buf);
    if (slot)
        PK11_FreeSlot(slot);
    if (privKeyList)
        SECKEY_DestroyPrivateKeyList(privKeyList);


    return result;

}