#include <memory.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <gcrypt.h>

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

enum READ_PARAM_MODE{
    READ_STRING = 1,
    READ_HEX = 2
};

/* read next line in file, skip commented out or empty */
char * read_line(FILE *fp) {
    char line[4096];
    char *p;

    do {
        if (!fgets(line, sizeof(line), fp)) {
            if (feof(fp))
                return NULL;
            abort();
        }
        p = strchr(line, '\n');
        if (!p)
            abort();
        *p = 0;
    } while (!*line || *line == '#');

    return strdup(line);
}

/* read a line from file, expect tag in expected, in mode 0 put hex decoded
 * value in allocated buffer of length len, in mode 1 reads a string */
void read_param(FILE *fp, enum READ_PARAM_MODE mode, char *expected,
                char **buffer, size_t *len) {
    char *line;
    char *pos;

    *buffer = NULL;

    line = read_line(fp);
    if (line == NULL) {
        fprintf(stderr, "end of file reached\n");
        abort();
    }

    if (memcmp(line, expected, strlen(expected)) != 0) {
        fprintf(stderr, "tag %s not found in line: %s\n", expected, line);
        abort();
    }
    if (line[strlen(expected)] != '=') {
        fprintf(stderr, "'=' separator not found\n");
        abort();
    }
    *len = strlen(&line[strlen(expected)+1]) / (int)mode;

    *buffer = malloc(*len);
    if (*buffer == NULL)
        abort();
    pos = *buffer;

    if (mode == READ_STRING) {
        for(char *s = &line[strlen(expected)+1]; *s; s += 1) {
            sscanf(s, "%c", pos);
            pos += 1;
        }
    } else {
        for(char *s = &line[strlen(expected)+1]; *s; s += 2) {
            sscanf(s, "%2hhx", pos);
            pos += 1;
        }
    }

    free(line);
}

gcry_sexp_t read_private_key(FILE *fp) {
    char *curve, *d;
    size_t len_curve, len_d;
    gcry_sexp_t key;

    read_param(fp, READ_STRING, "curve", &curve, &len_curve);
    fprintf(stderr, "read curve: %s\n", curve);
    read_param(fp, READ_HEX, "d", &d, &len_d);
    fprintf(stderr, "read d, len: %i\n", len_d);

    if (gcry_sexp_build(&key, NULL,
            "(private-key(ecc(curve %b)(d %b)))",
            len_curve, curve,
            len_d, d)) {
        fprintf(stderr, "private key construction failed\n");
        abort();
    }

    return key;
}

void print_hex(const char *s, size_t len)
{
    for(size_t i = 0; len > i; i++){
        fprintf(stderr, "%02hhX", (unsigned int) *(s + i));
    }
    printf("\n");
}

char *get_signature_from_expression(gcry_sexp_t *sig_sexp, size_t len){
    size_t out_r_len = len, out_s_len = len;
    unsigned char *out_s = NULL, *out_r = NULL, *sig = NULL;
    gcry_sexp_t s_tmp2 = NULL;
    gcry_sexp_t s_tmp = gcry_sexp_find_token(*sig_sexp, "sig-val", 0);

    if (s_tmp){
        s_tmp2 = s_tmp;
        s_tmp = gcry_sexp_find_token(s_tmp2, "ecdsa", 0);
        if (s_tmp){
            gcry_sexp_release(s_tmp2);
            s_tmp2 = s_tmp;
            s_tmp = gcry_sexp_find_token(s_tmp2, "r", 0);
            if (s_tmp){
                const char *p;
                size_t n;

                out_r = (char *)malloc(out_r_len);
                if (!out_r){
                    // err = gpg_error_from_syserror();
                    fprintf(stderr, "Failed to get memory for 'r'.\n");
                    gcry_sexp_release(s_tmp);
                    gcry_sexp_release(s_tmp2);
		            goto leave;
                }

                p = gcry_sexp_nth_data(s_tmp, 1, &n);

                if (n == out_r_len)
                    memcpy(out_r, p, out_r_len);
                else{
                    memset(out_r, 0, out_r_len - n);
                    memcpy(out_r + out_r_len - n, p, n);
                }
                gcry_sexp_release(s_tmp);
            }
            s_tmp = gcry_sexp_find_token(s_tmp2, "s", 0);
            if (s_tmp){
                const char *p;
                size_t n;

                out_s = (char *)malloc(out_s_len);
                if (!out_s){
                    // err = gpg_error_from_syserror();
                    fprintf(stderr, "Failed to get memory for 's'.\n");
                    gcry_sexp_release(s_tmp);
                    gcry_sexp_release(s_tmp2);
		            goto leave;
                }

                p = gcry_sexp_nth_data(s_tmp, 1, &n);

                if (n == out_s_len)
                    memcpy(out_s, p, out_s_len);
                else{
                    memset(out_s, 0, out_s_len - n);
                    memcpy(out_s + out_s_len - n, p, n);
                }
                gcry_sexp_release(s_tmp);
            }
        }
    } else {
        fprintf(stderr, "Signature not obtained correctly");
        abort();
    }

    gcry_sexp_release(s_tmp2);

    sig = (char *)malloc(out_r_len + out_s_len);
    memcpy(sig, out_r, out_r_len);
    memcpy(sig + out_r_len, out_s, out_s_len);
    free(out_r);
    free(out_s);

    leave:

    return sig;

}

void help(char *name) {
    printf("Usage: %s -i file -o file -t file -k file [-h]\n", name);
    printf("\n");
    printf(" -i file    File with data to sign.\n");
    printf(" -o file    File to write the signatures.\n");
    printf(" -t file    File to write the time to sign the hashes.\n");
    printf(" -k file    File with the private key params in txt format.\n");
    printf("            The file must include the curve and d params.\n");
    printf(" -s num     Size of each block of data to sign.\n");
    printf(" -h         This message.\n");
}

int main(int argc, char *argv[]) {
    FILE *fp;
    char *key_file_name = NULL, *in_file_name = NULL, *out_file_name = NULL, *time_file_name = NULL;
    int in_fd = -1, out_fd = -1, time_fd = -1;
    int opt;
    int result = 1, r_ret;
    gcry_error_t s_ret = NULL;
    size_t data_size = 32;
    unsigned char *data = NULL, *sig = NULL;
    gcry_sexp_t pkey = NULL;
    uint64_t time_before, time_after, time_diff;
    char *baseline_str;
    int baseline;
    size_t len_baseline;

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

    if ((pkey = read_private_key(fp)) == NULL){
        fprintf(stderr, "Can't read priv key \n");
        goto err;
    }

    read_param(fp, READ_STRING, "b", &baseline_str, &len_baseline);
    baseline = atoi(baseline_str);
    free(baseline_str);
    fprintf(stderr, "read baseline, value: %i\n", baseline);

    /* Allocate memory for the signature based on size in slen */
    sig = (unsigned char*)malloc(2 * baseline);
    if(!sig){
        fprintf(stderr, "Can't malloc enough space for signature size: %d\n", 2 * baseline);
        goto err;
    }

    while ((r_ret = read(in_fd, data, data_size)) > 0) {
        if (r_ret != data_size) {
            fprintf(stderr, "read less data than expected (truncated file?)\n");
            fprintf(stderr, "read %d bytes instead of %d\n", r_ret, data_size);
            goto err;
        }

        gcry_sexp_t data_sexp;
        gcry_sexp_t sig_sexp;
        size_t erroff;

        if (s_ret = gcry_sexp_build(&data_sexp, &erroff,
                "(data(flags raw)(value %b ))", data_size, data)) {
            fprintf(stderr, "data s-expression construction failed\n");
            fprintf(stderr, "error at pos %i\n", erroff);
            fprintf(stderr, "error code: %i\n", r_ret);
            fprintf(stderr, "failure: %s/%s\n",
                    gcry_strsource(r_ret), gcry_strerror(r_ret));
            goto err;
        }

        // time_after = get_time_after();
        time_before = get_time_before();

        /* Obtain the signature */
        s_ret = gcry_pk_sign(&sig_sexp, data_sexp, pkey);

        time_after = get_time_after();

        /* Check there was no error while obtaining the signature */
        if(s_ret != 0){
            fprintf(stderr, "gcry_pk_sign\n");
            goto err;
        }

        sig = get_signature_from_expression(&sig_sexp, baseline);

        time_diff = time_after - time_before;

        r_ret = write(time_fd, &time_diff, sizeof(time_diff));
        if (r_ret <= 0) {
            fprintf(stderr, "Write error on times\n");
            goto err;
        }

        r_ret = write(out_fd, sig, 2 * baseline);
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
    if (fp)
        fclose(fp);
    if (pkey)
        gcry_sexp_release(pkey);

    return result;

}