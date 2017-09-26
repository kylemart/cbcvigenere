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
#define GBUFFER_SIZE_KB (5 * 1000)

static char gbuffer[GBUFFER_SIZE_KB];
static size_t gbuffer_len;
static size_t gbuffer_pos;

/* global buffer update */
void gbfupdate(FILE* stream)
{
	gbuffer_len = fread(gbuffer, sizeof (char), sizeof gbuffer, stream);
	gbuffer_pos = 0;
}

/* global buffer get char */
int gbfgetc(FILE* stream)
{
	if (gbuffer_pos >= gbuffer_len)
		gbfupdate(stream);
	return (gbuffer_len > 0) ? gbuffer[gbuffer_pos++] : EOF;
}

/* scan stream for alpha char */
int fscanalpha(FILE* stream)
{
    int ch;
    while ((ch = gbfgetc(stream)) != EOF)
        if (isalpha(ch))
            break;
    return tolower(ch);
}

/* scan stream for n-alphas */
int fscannalphas(char* cbuff, int n, FILE* stream)
{
    int i;
    for (i = 0; i < n; ++i) {
        int ch = fscanalpha(stream);
        if (ch == EOF)
            return i;
        cbuff[i] = ch;
    }
    return i;
}

/* column-delimited print char */
void cdputc(int c, int* len)
{
    if (*len > 0 && *len % TEXT_WIDTH == 0)
        putchar('\n');
    putchar(c);
    *len += 1;
}

/* column-delimited print n-chars */
void cdnputs(const char* str, int n, int* len)
{
    for (int i = 0; i < n; ++i)
        cdputc(str[i], len);
}

/* exclusive or */
int xor(char x, char y)
{
    return (char) (((x - 'a' + y - 'a') % 26) + 'a');
}

/* block encrypt */
void bencrypt(char* block, const char* previous, const char* keyword, int bsize)
{
    for (int i = 0; i < bsize; ++i)
        block[i] = xor(xor(block[i], previous[i]), keyword[i]);
}

/* print plaintext */
int printpt(const char* pt_filename)
{
    FILE* pt = fopen(pt_filename, "r");
    if (pt == NULL) {
        fputs("Error: ", stderr);
        perror(pt_filename);
        return -1;
    }

    int len = 0;

    int ch;
    while ((ch = fscanalpha(pt)) != EOF)
        cdputc(ch, &len);
    putchar('\n');
    fclose(pt);

    return len;
}

/* print ciphertext */
int printct(const char* keyword, const char* init_vector, size_t bsize, const char* pt_filename)
{
    FILE* pt = fopen(pt_filename, "r");
    if (pt == NULL) {
        fputs("Error: ", stderr);
        perror(pt_filename);
        return -1;
    }

    char* current = malloc(bsize);
    char* previous = malloc(bsize);
    strncpy(previous, init_vector, bsize);

    int len = 0;

    int nread;
    while ((nread = fscannalphas(current, bsize, pt)) > 0) {
        if (nread < bsize) {
            int pad_len = bsize - nread;
            memset(current + nread, 'x', pad_len);
        }
        bencrypt(current, previous, keyword, bsize);
        cdnputs(current, bsize, &len);
        strncpy(previous, current, bsize);
    }
    putchar('\n');

    free(current);
    free(previous);
    fclose(pt);

    return len;
}

/* is lowercase alphas */
int isloweralphas(const char *str)
{
    while (*str != '\0') {
        if (!(isalpha(*str) && islower(*str)))
            return 0;
        ++str;
    }
    return 1;
}

/* program entry point */
int main(int argc, char* argv[])
{
    if (argc != 4) {
        fputs("Usage:\n", stderr);
        fprintf(stderr, "\t%s [filename] [keyword] [init_vector]\n", argv[0]);
        return EXIT_FAILURE;
    }

    char* filename = argv[1];
    char* keyword = argv[2];
    char* init_vector = argv[3];
    size_t bsize = strlen(keyword);

    if (!(isloweralphas(keyword) && isloweralphas(init_vector))) {
        fputs("Error: Keyword and init vector must be lowercase letters\n", stderr);
        return EXIT_FAILURE;
    } else if (bsize != strlen(init_vector)) {
        fputs("Error: Keyword and init vector must be equal length\n", stderr);
        return EXIT_FAILURE;
    }

    printf("CBC Vigenere by %s\n", AUTHOR);
    printf("Plaintext file name: %s\n", filename);
    printf("Vigenere keyword: %s\n", keyword);
    printf("Initialization vector: %s\n", init_vector);
    putchar('\n');
    puts("Clean Plaintext:");
    putchar('\n');
    int pt_len = printpt(filename);
    putchar('\n');
    puts("Ciphertext:");
    putchar('\n');
    int ct_len = printct(keyword, init_vector, bsize, filename);
    putchar('\n');
    printf("Number of characters in clean plaintext file: %d\n", pt_len);
    printf("Block size = %lu\n", bsize);
    printf("Number of pad characters added: %d\n", ct_len - pt_len);

    return (pt_len >= 0 && ct_len >= 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
