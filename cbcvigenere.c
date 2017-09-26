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
    static size_t buffer_size;
    static size_t buffer_index;
    static char buffer[BUFFER_CAPACITY_KB];
    static FILE* buffered;

    if (buffered != stream || buffer_index >= buffer_size) {
        buffer_size = fread(buffer, sizeof (char), sizeof buffer, stream);
        buffer_index = 0;
        buffered = stream;
    }
    return (buffer_size > 0) ? buffer[buffer_index++] : EOF;
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

int next_n_alphas(char* cbuff, int n, FILE* stream)
{
    int index;
    for (index = 0; index < n; ++index) {
        int c = next_alpha(stream);
        if (c == EOF)
            break;
        cbuff[index] = c;
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

void print_block(char* block, int* n)
{
    for (int index = 0; block[index] != '\0'; ++index) {
        col_delim_putc(block[index], n);
    }
}

char xor(char x, char y)
{
    return (char) (((x - 'a' + y - 'a') % 26) + 'a');
}

void encrypt_block(char* block, char* prev, char* key)
{
    for (int index = 0; block[index] != '\0'; ++index) {
        block[index] = xor(xor(block[index], prev[index]), key[index]);
    }
}

int print_plaintext(char* pt_path)
{
    FILE* pt = fopen(pt_path, "r");
    if (pt == NULL) {
        fputs("Error: ", stderr);
        perror(pt_path);
        return -1;
    }

    int n = 0;

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

int print_ciphertext(char* key, char* init_vector, size_t b_size, char* pt_path)
{
    FILE* pt = fopen(pt_path, "r");
    if (pt == NULL) {
        fputs("Error: ", stderr);
        perror(pt_path);
        return -1;
    }

    int n = 0;

    char* block = calloc(b_size + 1, sizeof (char));
    char* prev = calloc(b_size + 1, sizeof (char));
    strcpy(prev, init_vector);
    int read;
    while ((read = next_n_alphas(block, b_size, pt)) > 0) {
        if (read < b_size) {
            pad_block(block, read, 'x');
        }
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

int are_lower_alphas(char* str)
{
    for (int index = 0; str[index] != '\0'; ++index) {
        if (!(isalpha(str[index]) && islower(str[index])))
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

    char* pt_path = argv[1];
    char* key = argv[2];
    char* init_vector = argv[3];
    size_t b_size = strlen(key);

    if (!(are_lower_alphas(key) && are_lower_alphas(init_vector))) {
        fputs("Error: Key and init vector must be lowercase letters\n", stderr);
        return EXIT_FAILURE;
    } else if (b_size != strlen(init_vector)) {
        fputs("Error: Key and init vector must be equal length\n", stderr);
        return EXIT_FAILURE;
    }

    printf("CBC Vigenere by %s\n", AUTHOR);
    printf("Plaintext file name: %s\n", pt_path);
    printf("Vigenere keyword: %s\n", key);
    printf("Initialization vector: %s\n", init_vector);
    putchar('\n');
    puts("Clean Plaintext:");
    putchar('\n');
    int pt_len = print_plaintext(pt_path);
    putchar('\n');
    puts("Ciphertext:");
    putchar('\n');
    int ct_len = print_ciphertext(key, init_vector, b_size, pt_path);
    putchar('\n');
    printf("Number of characters in clean plaintext file: %d\n", pt_len);
    printf("Block size = %lu\n", b_size);
    printf("Number of pad characters added: %d\n", ct_len - pt_len);

    return (pt_len >= 0 && ct_len >= 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
