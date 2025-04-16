#ifndef CRYPTO_AES_H
#define CRYPTO_AES_H

/* Mã hoá AES-128-CBC.
 * Tham số:
 *   - plaintext: dữ liệu gốc cần mã hoá.
 *   - plaintext_len: độ dài dữ liệu gốc.
 *   - key: khóa 16 byte cho AES-128.
 *   - iv: vector khởi tạo 16 byte.
 *   - ciphertext: buffer chứa dữ liệu mã hoá.
 * Trả về: độ dài dữ liệu mã hoá.
 */
int aes_encrypt(const unsigned char *plaintext, int plaintext_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char *ciphertext);

/* Giải mã AES-128-CBC.
 * Tham số:
 *   - ciphertext: dữ liệu mã hoá.
 *   - ciphertext_len: độ dài dữ liệu mã hoá.
 *   - key: khóa 16 byte cho AES-128.
 *   - iv: vector khởi tạo 16 byte.
 *   - plaintext: buffer chứa dữ liệu giải mã.
 * Trả về: độ dài dữ liệu sau giải mã.
 */
int aes_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char *plaintext);

#endif // CRYPTO_AES_H
