#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// define mã lỗi
enum E_Error {
    E_OK = 0,                        // Thành công -> Success 
    E_ERR_UNKNOWN_KEYLEN,            //Kích thước khóa không xác định -> Error 
    E_ERR_MEM_ALLOC_FAILURE          //Cấp phát bộ nhớ thất bại -> Error 
};

// Bảng chuyển đổi Byte (S-Box) cho AES (sử dụng trong quá trình mã hóa)
unsigned char sBoxLookup[256] = {
    // 0      1     2     3     4     5     6     7     8     9      A     B     C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,  // 0
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,  // 1
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,  // 2
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,  // 3
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,  // 4
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,  // 5
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,  // 6
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,  // 7
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,  // 8
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,  // 9
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,  // A
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,  // B
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,  // C
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,  // D
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,  // E
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16   // F
};

// Bảng S-Box đảo cho AES (dùng trong quá trình giải mã)
unsigned char invSBoxLookup[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

// Bảng Rcon dùng cho việc mở rộng khóa
unsigned char rConTable[255] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
    0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
    0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d,
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab,
    0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d,
    0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25,
    0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01,
    0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d,
    0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa,
    0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a,
    0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02,
    0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
    0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
    0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb
};

// Định nghĩa kích thước khóa (16, 24 hoặc 32 byte)
enum E_KeyLen {
    KEYLEN_16 = 16,  // Khóa 128-bit
    KEYLEN_24 = 24,  // Khóa 192-bit
    KEYLEN_32 = 32   // Khóa 256-bit
};

// Lấy giá trị từ S-Box
unsigned char retrieveSBox(unsigned char value) {
    return sBoxLookup[value];
}

// Lấy giá trị từ S-Box đảo
unsigned char retrieveInvSBox(unsigned char value) {
    return invSBoxLookup[value];
}

// Xoay trái một word (4 byte)
void rotateWord(unsigned char *wordBuffer) {
    unsigned char tmp = wordBuffer[0];
    for (int i = 0; i < 3; i++) {
        wordBuffer[i] = wordBuffer[i+1];
    }
    wordBuffer[3] = tmp;
}

// Lấy giá trị từ bảng Rcon
unsigned char retrieveRCon(unsigned char index) {
    return rConTable[index];
}

// Hàm "core" cho việc lập lịch khóa (key scheduling)
void scheduleCore(unsigned char *wordBuffer, int iter) {
    rotateWord(wordBuffer);
    for (int i = 0; i < 4; i++) {
        wordBuffer[i] = retrieveSBox(wordBuffer[i]);
    }
    wordBuffer[0] ^= retrieveRCon(iter);
}

// Mở rộng khóa cho AES
void keyExpansion(unsigned char *expKey, unsigned char *origKey, enum E_KeyLen keyLen, size_t expKeyLen) {
    int currSize = 0;
    int rconIter = 1;
    unsigned char temp[4] = {0};
    // Sao chép key ban đầu vào phần mở rộng
    for (int i = 0; i < keyLen; i++) {
        expKey[i] = origKey[i];
    }
    currSize += keyLen;
    while (currSize < expKeyLen) {
        for (int i = 0; i < 4; i++) {
            temp[i] = expKey[currSize - 4 + i];
        }
        if (currSize % keyLen == 0) {
            scheduleCore(temp, rconIter++);
        }
        if (keyLen == KEYLEN_32 && (currSize % keyLen) == 16) {
            for (int i = 0; i < 4; i++)
                temp[i] = retrieveSBox(temp[i]);
        }
        for (int i = 0; i < 4; i++) {
            expKey[currSize] = expKey[currSize - keyLen] ^ temp[i];
            currSize++;
        }
    }
}

// Thay thế các byte trong state dùng S-Box
void substituteBytes(unsigned char *stateArr) {
    for (int i = 0; i < 16; i++) {
        stateArr[i] = retrieveSBox(stateArr[i]);
    }
}

// Dịch chuyển các hàng trong state
void rowShift(unsigned char *stateArr) {
    for (int i = 0; i < 4; i++) {
        // Dịch hàng thứ i sang trái i lần
        for (int j = 0; j < i; j++) {
            unsigned char tempVal = stateArr[i * 4];
            for (int k = 0; k < 3; k++) {
                stateArr[i * 4 + k] = stateArr[i * 4 + k + 1];
            }
            stateArr[i * 4 + 3] = tempVal;
        }
    }
}

// Dịch chuyển (rotate left) một hàng cụ thể
void shiftRowLeft(unsigned char *row, unsigned char count) {
    for (int i = 0; i < count; i++) {
        unsigned char temp = row[0];
        for (int j = 0; j < 3; j++) {
            row[j] = row[j + 1];
        }
        row[3] = temp;
    }
}

// Thêm khóa vòng vào state
void addRound(unsigned char *stateArr, unsigned char *roundKey) {
    for (int i = 0; i < 16; i++) {
        stateArr[i] ^= roundKey[i];
    }
}

// Nhân trong trường Galois (dùng trong mixColumns)
unsigned char galoisMultiply(unsigned char a, unsigned char b) {
    unsigned char product = 0, hiBit;
    for (int counter = 0; counter < 8; counter++) {
        if (b & 1)
            product ^= a;
        hiBit = (a & 0x80);
        a <<= 1;
        if (hiBit)
            a ^= 0x1b;
        b >>= 1;
    }
    return product;
}

// Trộn (mix) các cột của state
void mixCols(unsigned char *stateArr) {
    unsigned char col[4];
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            col[j] = stateArr[j * 4 + i];
        }
        // Áp dụng mix cho một cột
        unsigned char backup[4];
        for (int k = 0; k < 4; k++) backup[k] = col[k];
        col[0] = galoisMultiply(backup[0], 2) ^ galoisMultiply(backup[3], 1) ^ galoisMultiply(backup[2], 1) ^ galoisMultiply(backup[1], 3);
        col[1] = galoisMultiply(backup[1], 2) ^ galoisMultiply(backup[0], 1) ^ galoisMultiply(backup[3], 1) ^ galoisMultiply(backup[2], 3);
        col[2] = galoisMultiply(backup[2], 2) ^ galoisMultiply(backup[1], 1) ^ galoisMultiply(backup[0], 1) ^ galoisMultiply(backup[3], 3);
        col[3] = galoisMultiply(backup[3], 2) ^ galoisMultiply(backup[2], 1) ^ galoisMultiply(backup[1], 1) ^ galoisMultiply(backup[0], 3);
        for (int j = 0; j < 4; j++) {
            stateArr[j * 4 + i] = col[j];
        }
    }
}

// Thực hiện một vòng mã hóa AES
void encryptionRound(unsigned char *stateArr, unsigned char *roundKey) {
    substituteBytes(stateArr);
    rowShift(stateArr);
    mixCols(stateArr);
    addRound(stateArr, roundKey);
}

// Tạo khóa vòng từ khóa mở rộng
void generateRoundKey(unsigned char *expKey, unsigned char *roundKey) {
    for (int col = 0; col < 4; col++) {
        for (int row = 0; row < 4; row++)
            roundKey[col + row * 4] = expKey[col * 4 + row];
    }
}

// Hàm chính của thuật toán mã hóa AES
void mainEncryption(unsigned char *stateArr, unsigned char *expKey, int rounds) {
    unsigned char roundKey[16];
    generateRoundKey(expKey, roundKey);
    addRound(stateArr, roundKey);
    for (int i = 1; i < rounds; i++) {
        generateRoundKey(expKey + 16 * i, roundKey);
        encryptionRound(stateArr, roundKey);
    }
    generateRoundKey(expKey + 16 * rounds, roundKey);
    substituteBytes(stateArr);
    rowShift(stateArr);
    addRound(stateArr, roundKey);
}

// Hàm mã hóa AES
char encryptAES(unsigned char *inData, unsigned char *outData, unsigned char *keyData, enum E_KeyLen keySize) {
    int rounds;
    int expKeySize;
    unsigned char *expandedKey;
    unsigned char block[16];
    // Xác định số vòng dựa trên kích thước khóa
    switch (keySize) {
        case KEYLEN_16:
            rounds = 10;
            break;
        case KEYLEN_24:
            rounds = 12;
            break;
        case KEYLEN_32:
            rounds = 14;
            break;
        default:
            return E_ERR_UNKNOWN_KEYLEN;
    }
    expKeySize = 16 * (rounds + 1);
    expandedKey = (unsigned char *)malloc(expKeySize * sizeof(unsigned char));
    if (expandedKey == NULL) {
        return E_ERR_MEM_ALLOC_FAILURE;
    } else {
        // Gán khối dữ liệu từ inData vào block (theo thứ tự cột)
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++)
                block[i + j * 4] = inData[i * 4 + j];
        }
        keyExpansion(expandedKey, keyData, keySize, expKeySize);
        mainEncryption(block, expandedKey, rounds);
        // Gán kết quả vào outData theo thứ tự hàng
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++)
                outData[i * 4 + j] = block[i + j * 4];
        }
        free(expandedKey);
        expandedKey = NULL;
    }
    return E_OK;
}

// Thay thế các byte trong state theo S-Box đảo (dùng cho giải mã)
void invSubstituteBytes(unsigned char *stateArr) {
    for (int i = 0; i < 16; i++) {
        stateArr[i] = retrieveInvSBox(stateArr[i]);
    }
}

// Dịch ngược dịch chuyển các hàng trong state
void invRowShift(unsigned char *stateArr) {
    for (int i = 0; i < 4; i++) {
        // Dịch hàng thứ i sang phải i lần
        for (int j = 0; j < i; j++) {
            unsigned char temp = stateArr[i * 4 + 3];
            for (int k = 3; k > 0; k--) {
                stateArr[i * 4 + k] = stateArr[i * 4 + k - 1];
            }
            stateArr[i * 4] = temp;
        }
    }
}

// Dịch ngược một hàng cụ thể sang phải
void shiftRowRight(unsigned char *row, unsigned char count) {
    for (int i = 0; i < count; i++) {
        unsigned char temp = row[3];
        for (int j = 3; j > 0; j--) {
            row[j] = row[j - 1];
        }
        row[0] = temp;
    }
}

// Trộn ngược (inverse mix) các cột trong state
void invMixCols(unsigned char *stateArr) {
    unsigned char col[4];
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++)
            col[j] = stateArr[j * 4 + i];
        unsigned char backup[4];
        for (int k = 0; k < 4; k++) backup[k] = col[k];
        col[0] = galoisMultiply(backup[0], 14) ^ galoisMultiply(backup[3], 9) ^ galoisMultiply(backup[2], 13) ^ galoisMultiply(backup[1], 11);
        col[1] = galoisMultiply(backup[1], 14) ^ galoisMultiply(backup[0], 9) ^ galoisMultiply(backup[3], 13) ^ galoisMultiply(backup[2], 11);
        col[2] = galoisMultiply(backup[2], 14) ^ galoisMultiply(backup[1], 9) ^ galoisMultiply(backup[0], 13) ^ galoisMultiply(backup[3], 11);
        col[3] = galoisMultiply(backup[3], 14) ^ galoisMultiply(backup[2], 9) ^ galoisMultiply(backup[1], 13) ^ galoisMultiply(backup[0], 11);
        for (int j = 0; j < 4; j++)
            stateArr[j * 4 + i] = col[j];
    }
}

// Thực hiện một vòng giải mã AES
void decryptionRound(unsigned char *stateArr, unsigned char *roundKey) {
    invRowShift(stateArr);
    invSubstituteBytes(stateArr);
    addRound(stateArr, roundKey);
    invMixCols(stateArr);
}

// Hàm chính của giải mã AES
void mainDecryption(unsigned char *stateArr, unsigned char *expKey, int rounds) {
    unsigned char roundKey[16];
    generateRoundKey(expKey + 16 * rounds, roundKey);
    addRound(stateArr, roundKey);
    for (int i = rounds - 1; i > 0; i--) {
        generateRoundKey(expKey + 16 * i, roundKey);
        decryptionRound(stateArr, roundKey);
    }
    generateRoundKey(expKey, roundKey);
    invRowShift(stateArr);
    invSubstituteBytes(stateArr);
    addRound(stateArr, roundKey);
}

// Hàm giải mã AES
char decryptAES(unsigned char *inData, unsigned char *outData, unsigned char *keyData, enum E_KeyLen keySize) {
    int rounds;
    int expKeySize;
    unsigned char *expandedKey;
    unsigned char block[16];
    switch (keySize) {
        case KEYLEN_16:
            rounds = 10;
            break;
        case KEYLEN_24:
            rounds = 12;
            break;
        case KEYLEN_32:
            rounds = 14;
            break;
        default:
            return E_ERR_UNKNOWN_KEYLEN;
    }
    expKeySize = 16 * (rounds + 1);
    expandedKey = (unsigned char *)malloc(expKeySize * sizeof(unsigned char));
    if (expandedKey == NULL) {
        return E_ERR_MEM_ALLOC_FAILURE;
    } else {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++)
                block[i + j * 4] = inData[i * 4 + j];
        }
        keyExpansion(expandedKey, keyData, keySize, expKeySize);
        mainDecryption(block, expandedKey, rounds);
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++)
                outData[i * 4 + j] = block[i + j * 4];
        }
        free(expandedKey);
        expandedKey = NULL;
    }
    return E_OK;
}

// Hàm chính
int main() {
    unsigned char plainText[16], secretKey[16];
    char inputFile[] = "input.txt";

    FILE *fp = fopen(inputFile, "r");
    if (!fp) {
        fprintf(stderr, "Lỗi: Không thể mở file %s\n", inputFile);
        exit(1);
    }

    char buffer[256];
    if (!fgets(buffer, sizeof(buffer), fp)) {
        fprintf(stderr, "Lỗi: Không đọc được dòng đầu của file %s\n", inputFile);
        fclose(fp);
        exit(1);
    }
    buffer[strcspn(buffer, "\r\n")] = 0;
    if (strncmp(buffer, "\xEF\xBB\xBF", 3) == 0) {
        fprintf(stderr, "Lỗi: File %s chưa BOM UTF-8. Hãy lưu theo dạng ASCII\n", inputFile);
        fclose(fp);
        exit(1);
    }
    if (strncmp(buffer, "plaintext: \"", 12) != 0) {
        fprintf(stderr, "Lỗi: Dòng đầu phải bắt đầu bằng 'plaintext: \"'. Nội dung đọc được: '%s'\n", buffer);
        fclose(fp);
        exit(1);
    }
    if (strlen(buffer + 12) < 17 || buffer[12 + 16] != '"') {
        fprintf(stderr, "Lỗi: Plaintext phải có đúng 16 ký tự trong dấu ngoặc kép, đọc được: '%s'\n", buffer + 12);
        fclose(fp);
        exit(1);
    }
    strncpy((char *)plainText, buffer + 12, 16);

    if (!fgets(buffer, sizeof(buffer), fp)) {
        fprintf(stderr, "Lỗi: Không đọc được dòng thứ hai của file %s\n", inputFile);
        fclose(fp);
        exit(1);
    }
    buffer[strcspn(buffer, "\r\n")] = 0;
    if (strncmp(buffer, "key: \"", 6) != 0) {
        fprintf(stderr, "Lỗi: Dòng thứ hai phải bắt đầu bằng 'key: \"'. Nội dung đọc được: '%s'\n", buffer);
        fclose(fp);
        exit(1);
    }
    if (strlen(buffer + 6) < 17 || buffer[6 + 16] != '"') {
        fprintf(stderr, "Lỗi: Key phải có đúng 16 ký tự trong dấu ngoặc kép, đọc được: '%s'\n", buffer + 6);
        fclose(fp);
        exit(1);
    }
    strncpy((char *)secretKey, buffer + 6, 16);
    fclose(fp);

    // Mã hóa plaintext
    unsigned char cipherText[16];
    encryptAES(plainText, cipherText, secretKey, KEYLEN_16);

    FILE *fpOut = fopen("output.txt", "w");
    if (!fpOut) {
        fprintf(stderr, "Lỗi: Không thể mở file output.txt\n");
        exit(1);
    }
    fprintf(fpOut, "Ciphertext (HEX format):\n");
    for (int i = 0; i < 16; i++) {
        fprintf(fpOut, "%02x%c", cipherText[i], ((i + 1) % 16) ? ' ' : '\n');
    }
    fclose(fpOut);

    // Giải mã ciphertext
    unsigned char recoveredText[16];
    decryptAES(cipherText, recoveredText, secretKey, KEYLEN_16);

    FILE *fpDec = fopen("decrypt.txt", "w");
    if (!fpDec) {
        fprintf(stderr, "Lỗi: Không thể mở file decrypt.txt\n");
        exit(1);
    }
    fprintf(fpDec, "Decrypted text (HEX format):\n");
    for (int i = 0; i < 16; i++) {
        fprintf(fpDec, "%02x%c", recoveredText[i], ((i + 1) % 16) ? ' ' : '\n');
    }
    fclose(fpDec);

    printf("Mã hóa và giải mã hoàn tất. Kiểm tra output.txt và decrypt.txt\n");
    return 0;
}
