#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#define SPLITSYM_REMOVE_PRIVATE 0x00000001

BOOL WINAPI SplitSymbols(PSTR image_name, PCSTR symbols_path, PSTR symbol_file_path, ULONG flags);
BOOL WINAPI ReBaseImage(PCSTR current_image_name, PCSTR symbol_path, BOOL rebase, BOOL rebase_system_file_ok,
						BOOL going_down, ULONG check_image_size, ULONG *old_image_size, ULONG_PTR *old_image_base,
						ULONG *new_image_size, ULONG_PTR *new_image_base, ULONG timestamp);

#include "test_assert.h"

static IMAGE_NT_HEADERS read_headers(const char *path) {
	IMAGE_DOS_HEADER dos;
	IMAGE_NT_HEADERS headers;
	FILE *file = fopen(path, "rb");
	TEST_CHECK_MSG(file != NULL, "fopen(%s) failed", path);
	TEST_CHECK_EQ(1, fread(&dos, sizeof(dos), 1, file));
	TEST_CHECK_EQ(IMAGE_DOS_SIGNATURE, dos.e_magic);
	TEST_CHECK_EQ(0, fseek(file, dos.e_lfanew, SEEK_SET));
	TEST_CHECK_EQ(1, fread(&headers, sizeof(headers), 1, file));
	TEST_CHECK_EQ(IMAGE_NT_SIGNATURE, headers.Signature);
	fclose(file);
	return headers;
}

static void copy_file(const char *source, const char *destination) {
	unsigned char buffer[4096];
	size_t count;
	FILE *input = fopen(source, "rb");
	FILE *output;
	TEST_CHECK_MSG(input != NULL, "fopen(%s) failed", source);
	output = fopen(destination, "wb");
	TEST_CHECK_MSG(output != NULL, "fopen(%s) failed", destination);
	while ((count = fread(buffer, 1, sizeof(buffer), input)) != 0)
		TEST_CHECK_EQ(count, fwrite(buffer, 1, count, output));
	TEST_CHECK_EQ(0, ferror(input));
	TEST_CHECK_EQ(0, fclose(input));
	TEST_CHECK_EQ(0, fclose(output));
}

int main(void) {
	const char *copy_path = "test_imagehlp_work.exe";
	const char *symbols_path = "imagehlp-symbols";
	char module_path[MAX_PATH];
	char debug_path[MAX_PATH] = {0};
	DWORD module_len = GetModuleFileNameA(NULL, module_path, sizeof(module_path));
	TEST_CHECK_MSG(module_len > 0 && module_len < sizeof(module_path), "GetModuleFileNameA failed: %lu",
				   (unsigned long)GetLastError());
	DeleteFileA(copy_path);
	copy_file(module_path, copy_path);

	IMAGE_NT_HEADERS before = read_headers(copy_path);
	TEST_CHECK_MSG(SplitSymbols((char *)copy_path, symbols_path, debug_path, SPLITSYM_REMOVE_PRIVATE),
				   "SplitSymbols failed: %lu", (unsigned long)GetLastError());
	TEST_CHECK_MSG(strstr(debug_path, ".dbg") != NULL, "unexpected debug path: %s", debug_path);
	TEST_CHECK_MSG(GetFileAttributesA(debug_path) != INVALID_FILE_ATTRIBUTES, "missing debug file %s", debug_path);

	IMAGE_NT_HEADERS stripped = read_headers(copy_path);
	TEST_CHECK(stripped.FileHeader.Characteristics & IMAGE_FILE_LINE_NUMS_STRIPPED);
	TEST_CHECK(stripped.FileHeader.Characteristics & IMAGE_FILE_DEBUG_STRIPPED);

	ULONG old_size = 0;
	ULONG new_size = 0;
	ULONG_PTR old_base = 0;
	ULONG_PTR new_base = before.OptionalHeader.ImageBase + 0x10000;
	TEST_CHECK_MSG(ReBaseImage(copy_path, symbols_path, TRUE, FALSE, FALSE, 0, &old_size, &old_base, &new_size,
							   &new_base, 0x12345678),
				   "ReBaseImage failed: %lu", (unsigned long)GetLastError());
	TEST_CHECK_EQ(before.OptionalHeader.SizeOfImage, old_size);
	TEST_CHECK_EQ(before.OptionalHeader.ImageBase, old_base);
	TEST_CHECK_EQ(before.OptionalHeader.SizeOfImage, new_size);
	TEST_CHECK_EQ(before.OptionalHeader.ImageBase + 0x10000, new_base);

	IMAGE_NT_HEADERS rebased = read_headers(copy_path);
	TEST_CHECK_EQ(0x12345678, rebased.FileHeader.TimeDateStamp);
	TEST_CHECK_EQ(before.OptionalHeader.ImageBase + 0x10000, rebased.OptionalHeader.ImageBase);
	TEST_CHECK_MSG(rebased.OptionalHeader.CheckSum != 0, "ReBaseImage did not set the PE checksum");

	DeleteFileA(copy_path);
	DeleteFileA(debug_path);
	puts("ImageHlp symbol splitting and PE rebasing validated");
	return EXIT_SUCCESS;
}
