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
#define BUFFER_CAPACITY_KB (5 * 1024)

int buffer_getc(FILE* stream)
{
    static size_t size;
    static size_t index;
    static FILE* buffered;
    static char buffer[BUFFER_CAPACITY_KB];

    if (buffered != stream || index >= size) {
        size = fread(buffer, sizeof (char), sizeof buffer, stream);
        index = 0;
        buffered = stream;
    }
    return (size > 0) ? buffer[index++] : EOF;
}

int next_alpha(FILE* stream)
{
    int c;
    while ((c = buffer_getc(stream)) != EOF) {
        if (isalpha(c))
            return tolower(c);
    }
    return EOF;
}

int next_n_alphas(char* dest, int n, FILE* stream)
{
    int index;
    for (index = 0; index < n; ++index) {
        int c = next_alpha(stream);
        if (c == EOF)
            break;
        dest[index] = c;
    }
    return index;
}

void col_delim_putc(char c, int* n)
{
    if (*n > 0 && *n % TEXT_WIDTH == 0)
        putchar('\n');
    putchar(c);
    *n += 1;
}

void print_block(const char* block, int* n)
{
    for (int index = 0; block[index] != '\0'; ++index) {
        col_delim_putc(block[index], n);
    }
}

char xor(char x, char y)
{
    return (char) (((x - 'a' + y - 'a') % 26) + 'a');
}

void encrypt_block(char* block, const char* prev, const char* key)
{
    for (int index = 0; block[index] != '\0'; ++index) {
        block[index] = xor(xor(block[index], prev[index]), key[index]);
    }
}

int print_pt(const char* pt_path)
{
    int n = 0;

    FILE* pt = fopen(pt_path, "r");
    if (pt == NULL) {
        fputs("Error: ", stderr);
        perror(pt_path);
        return -1;
    }
    int c;
    while ((c = next_alpha(pt)) != EOF) {
        col_delim_putc(c, &n);
    }
    putchar('\n');
    fclose(pt);

    return n;
}

void pad_block(char* block, size_t from_index, char pad_c)
{
    for (int index = from_index; block[index] != '\0'; ++index) {
        block[index] = pad_c;
    }
}

int print_ct(const char* key, const char* iv, size_t b_size, const char* pt_path)
{
    int n = 0;

    FILE* pt = fopen(pt_path, "r");
    if (pt == NULL) {
        fputs("Error: ", stderr);
        perror(pt_path);
        return -1;
    }
    char* block = calloc(b_size + 1, sizeof (char));
    char* prev = calloc(b_size + 1, sizeof (char));
    strcpy(prev, iv);

    int read;
    while ((read = next_n_alphas(block, b_size, pt)) > 0) {
        if (read < b_size)
            pad_block(block, read, 'x');
        encrypt_block(block, prev, key);
        print_block(block, &n);
        strcpy(prev, block);
    }
    putchar('\n');

    free(block);
    free(prev);
    fclose(pt);

    return n;
}

int are_lower(const char* str)
{
    for (int index = 0; str[index] != '\0'; ++index) {
        if (!islower(str[index]))
            return 0;
    }
    return 1;
}

int main(int argc, char* argv[])
{
    if (argc != 4) {
        fputs("Usage:\n", stderr);
        fprintf(stderr, "\t%s [filename] [key] [init_vector]\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char* pt_path = argv[1];
    const char* key = argv[2];
    const char* iv = argv[3];
    size_t b_size = strlen(key);

    if (b_size != strlen(iv)) {
        fputs("Error: Key and init vector must be equal length\n", stderr);
        return EXIT_FAILURE;
    } else if (!(are_lower(key) && are_lower(iv))) {
        fputs("Error: Key and init vector must be lowercase letters\n", stderr);
        return EXIT_FAILURE;
    }

    printf("CBC Vigenere by %s\n", AUTHOR);
    printf("Plaintext file name: %s\n", pt_path);
    printf("Vigenere keyword: %s\n", key);
    printf("Initialization vector: %s\n", iv);
    puts("\nClean Plaintext:\n");
    int pt_len = print_pt(pt_path);
    puts("\nCiphertext:\n");
    int ct_len = print_ct(key, iv, b_size, pt_path);
    printf("\nNumber of characters in clean plaintext file: %d\n", pt_len);
    printf("Block size = %lu\n", b_size);
    printf("Number of pad characters added: %d\n", ct_len - pt_len);

    return (pt_len >= 0 && ct_len >= 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
