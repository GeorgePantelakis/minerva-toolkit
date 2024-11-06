#include <memory.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>

#include "gnutls/gnutls.h"
#include "gnutls/abstract.h"

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

static char *readfile(const char *filename, size_t *size_out)
{
    FILE *fp;
    long k;
    size_t size, pos, n, _out;
    char *buf;

    size_out = size_out ? size_out : &_out;

    fp = fopen(filename, "rb");
    size = 0;
    buf = 0;

    if (!fp) {
        goto fail;
    }

    fseek(fp, 0L, SEEK_END);
    k = ftell(fp);

    if (k < 0) goto fail;

    size = (size_t)k;
    *size_out = size;

    rewind(fp);

    buf = (char *)malloc(size ? size : 1);
    if (!buf) {
        goto fail;
    }

    pos = 0;
    while ((n = fread(buf + pos, 1, size - pos, fp))) {
        pos += n;
    }

    if (pos != size) {
        goto fail;
    }

    fclose(fp);
    *size_out = size;
    return buf;

fail:
    if (fp) {
        fclose(fp);
    }

    if (buf) {
        free(buf);
    }

    *size_out = size;
    return NULL;
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
    char *key_file_name = NULL, *in_file_name = NULL, *out_file_name = NULL, *time_file_name = NULL;
    int in_fd = -1, out_fd = -1, time_fd = -1;
    int opt;
    int result = 1, r_ret, ret = -1;
    size_t data_size = 32, sig_len_max = 256, privkey_size = 0;
    unsigned char *data = NULL, *sig = NULL;
    uint64_t time_before, time_after, time_diff;

    gnutls_privkey_t privkey;
    gnutls_datum_t data_datum = { NULL, 0 };
    gnutls_datum_t sig_datum = { NULL, 0 };
    gnutls_datum_t privkey_datum = { NULL, 0 };

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

    privkey_datum.data = (void *)readfile(key_file_name, &privkey_size);
	privkey_datum.size = privkey_size;
    if (!privkey_datum.data){
        fprintf(stderr, "Can't open key file %s\n", key_file_name);
        goto err;
    }

    data = malloc(data_size);
    data_datum.data = data;
    data_datum.size = data_size;
    if (!data){
        fprintf(stderr, "Can't malloc enough space for data size: %d\n", data_size);
        goto err;
    }

    ret = gnutls_privkey_init(&privkey);
	if (ret < 0) {
		fprintf(stderr, "Can't initialize private key: %s\n",
			gnutls_strerror(ret));
		goto err;
	}

    ret = gnutls_privkey_import_x509_raw(privkey, &privkey_datum, GNUTLS_X509_FMT_PEM, NULL, 0);
	if (ret < 0) {
		fprintf(stderr, "Can't read private key: %s\n",
			gnutls_strerror(ret));
		goto err;
	}

    /* Allocate memory for the signature based on size in slen */
    sig = (unsigned char*)malloc(sig_len_max);
    if(!sig){
        fprintf(stderr, "Can't malloc enough space for signature size: %d\n", sig_len_max);
        goto err;
    }

    while ((r_ret = read(in_fd, data, data_size)) > 0) {
        if (r_ret != data_size) {
            fprintf(stderr, "read less data than expected (truncated file?)\n");
            fprintf(stderr, "read %d bytes instead of %d\n", r_ret, data_size);
            goto err;
        }

        time_before = get_time_before();

        /* Singing data */
        ret = gnutls_privkey_sign_data2(privkey, GNUTLS_SIGN_ECDSA_SHA256, 0, &data_datum, &sig_datum);
        if (ret < 0) {
            fprintf(stderr, "gnutls_privkey_sign_data2\n");
            goto err;
        }

        time_after = get_time_after();

        time_diff = time_after - time_before;

        r_ret = write(time_fd, &time_diff, sizeof(time_diff));
        if (r_ret <= 0) {
            fprintf(stderr, "Write error on times\n");
            goto err;
        }

        r_ret = write(out_fd, sig_datum.data, sig_datum.size);
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
    if (privkey_datum.data != NULL) {
		gnutls_privkey_deinit(privkey);
    }

    return result;

}