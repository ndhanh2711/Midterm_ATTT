#ifndef CRYPTO_DES_H
#define CRYPTO_DES_H

/* Mã hoá DES-CBC.
 * Tham số:
 *   - plaintext: dữ liệu gốc cần mã hoá.
 *   - plaintext_len: độ dài dữ liệu gốc.
 *   - key: khóa 8 byte cho DES.
 *   - iv: vector khởi tạo 8 byte.
 *   - ciphertext: buffer chứa dữ liệu mã hoá.
 * Trả về: độ dài dữ liệu mã hoá.
 */
int des_encrypt(const unsigned char *plaintext, int plaintext_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char *ciphertext);

/* Giải mã DES-CBC.
 * Tham số:
 *   - ciphertext: dữ liệu mã hoá.
 *   - ciphertext_len: độ dài dữ liệu mã hoá.
 *   - key: khóa 8 byte cho DES.
 *   - iv: vector khởi tạo 8 byte.
 *   - plaintext: buffer chứa dữ liệu giải mã.
 * Trả về: độ dài dữ liệu sau giải mã.
 */
int des_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char *plaintext);

#endif // CRYPTO_DES_H
