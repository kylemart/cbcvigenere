//------------------------------------------------------------------
// University of Central Florida
// CIS3360 - Fall 2017
// Program Author: Kyle Martinez
//------------------------------------------------------------------

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>

#define AUTHOR "Kyle Martinez"
#define TEXT_WIDTH 80
#define BLOCK_PADDING 'x'
#define BUFFER_CAPACITY_KB (5 * 1024)

int buffer_getc(FILE *stream)
{
    static size_t size;
    static size_t index;
    static FILE *buffered;
    static char buffer[BUFFER_CAPACITY_KB];

    if (buffered != stream || index >= size) {
        size = fread(buffer, sizeof (char), sizeof buffer, stream);
        index = 0;
        buffered = stream;
    }
    return (size > 0) ? buffer[index++] : EOF;
}

int next_alpha(FILE *stream)
{
    int c;
    while ((c = buffer_getc(stream)) != EOF) {
        if (isalpha(c))
            return c;
    }
    return EOF;
}

size_t next_n_alphas(char *dest, size_t n, FILE *stream)
{
    size_t index;
    for (index = 0; index < n; ++index) {
        int c = next_alpha(stream);
        if (c == EOF)
            break;
        dest[index] = c;
    }
    return index;
}

int are_lower(const char *str)
{
    for (size_t index = 0; str[index] != '\0'; ++index) {
        if (!islower(str[index]))
            return 0;
    }
    return 1;
}

void col_delim_putc(char c, size_t *n)
{
    if (*n > 0 && *n % TEXT_WIDTH == 0)
        putchar('\n');
    putchar(c);
    *n += 1;
}

void print_block(const char *block, size_t *n)
{
    for (size_t index = 0; block[index] != '\0'; ++index) {
        col_delim_putc(block[index], n);
    }
}

char xor(char x, char y)
{
    const char ALPHABET_LENGTH = 26;
    return ((x - 'a' + y - 'a') % ALPHABET_LENGTH) + 'a';
}

void encrypt_block(char *block, const char *prev, const char *key)
{
    for (size_t index = 0; block[index] != '\0'; ++index) {
        block[index] = xor(xor(block[index], prev[index]), key[index]);
    }
}

void format_block(char *block, size_t n_read, size_t b_size)
{
    for (size_t index = 0; index < n_read; ++index) {
        block[index] = tolower(block[index]);
    }
    memset(block + n_read, BLOCK_PADDING, b_size - n_read);
}

size_t print_ct(const char *key, const char *iv, size_t b_size, FILE *pt)
{
    size_t n = 0;

    long int pt_offset = ftell(pt);

    char *current = calloc(b_size + 1, sizeof (char));
    char *previous = calloc(b_size + 1, sizeof (char));
    strcpy(previous, iv);

    size_t n_read;
    while ((n_read = next_n_alphas(current, b_size, pt)) > 0) {
        format_block(current, n_read, b_size);
        encrypt_block(current, previous, key);
        print_block(current, &n);
        strcpy(previous, current);
    }
    putchar('\n');

    free(current);
    free(previous);

    fseek(pt, pt_offset, SEEK_SET);

    return n;
}

size_t print_pt(FILE *pt)
{
    size_t n = 0;

    long int pt_offset = ftell(pt);

    int c;
    while ((c = next_alpha(pt)) != EOF) {
        col_delim_putc(tolower(c), &n);
    }
    putchar('\n');

    fseek(pt, pt_offset, SEEK_SET);

    return n;
}

int main(int argc, char *argv[])
{
    if (argc != 4) {
        fputs("Usage:\n", stderr);
        fprintf(stderr, "\t%s [filename] [key] [init_vector]\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *pt_path = argv[1];
    const char *key = argv[2];
    const char *iv = argv[3];

    size_t b_size = strlen(key);
    FILE *pt = fopen(pt_path, "r");

    if (b_size != strlen(iv)) {
        fputs("Error: Key and init vector must be equal length\n", stderr);
        return EXIT_FAILURE;
    } else if (!(are_lower(key) && are_lower(iv))) {
        fputs("Error: Key and init vector must be lowercase letters\n", stderr);
        return EXIT_FAILURE;
    } else if (!pt) {
        fputs("Error: ", stderr);
        perror(pt_path);
        return EXIT_FAILURE;
    }

    printf("CBC Vigenere by %s\n", AUTHOR);
    printf("Plaintext file name: %s\n", pt_path);
    printf("Vigenere keyword: %s\n", key);
    printf("Initialization vector: %s\n", iv);
    puts("\nClean Plaintext:\n");
    size_t pt_len = print_pt(pt);
    puts("\nCiphertext:\n");
    size_t ct_len = print_ct(key, iv, b_size, pt);
    printf("\nNumber of characters in clean plaintext file: %lu\n", pt_len);
    printf("Block size = %lu\n", b_size);
    printf("Number of pad characters added: %lu\n", ct_len - pt_len);

    fclose(pt);

    return EXIT_SUCCESS;
}
