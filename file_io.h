#ifndef FILE_IO_H
#define FILE_IO_H

/* Hàm đọc file dưới dạng binary.
 * Tham số:
 *   - filename: tên file cần đọc.
 *   - length: con trỏ lưu kích thước dữ liệu đọc được.
 * Trả về: buffer chứa dữ liệu đã đọc.
 */
unsigned char* read_file(const char *filename, long *length);

/* Hàm ghi dữ liệu dạng binary vào file.
 * Tham số:
 *   - filename: tên file ghi dữ liệu.
 *   - data: dữ liệu cần ghi.
 *   - length: kích thước dữ liệu.
 */
void write_file(const char *filename, unsigned char *data, long length);

#endif // FILE_IO_H
