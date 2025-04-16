#include <stdio.h>
#include <stdlib.h>
#include "file_io.h"

unsigned char* read_file(const char *filename, long *length) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        perror("Không thể mở file để đọc");
        exit(EXIT_FAILURE);
    }
    fseek(fp, 0, SEEK_END);
    *length = ftell(fp);
    rewind(fp);

    unsigned char *buffer = (unsigned char*)malloc(*length);
    if (!buffer) {
        perror("Không đủ bộ nhớ");
        fclose(fp);
        exit(EXIT_FAILURE);
    }

    if (fread(buffer, 1, *length, fp) != *length) {
        perror("Đọc file lỗi");
        free(buffer);
        fclose(fp);
        exit(EXIT_FAILURE);
    }
    fclose(fp);
    return buffer;
}

void write_file(const char *filename, unsigned char *data, long length) {
    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        perror("Không thể mở file để ghi");
        exit(EXIT_FAILURE);
    }
    if (fwrite(data, 1, length, fp) != (size_t)length) {
        perror("Ghi file lỗi");
        fclose(fp);
        exit(EXIT_FAILURE);
    }
    fclose(fp);
}
