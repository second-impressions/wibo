#include <stdarg.h>
#include <windows.h>

#include "test_assert.h"

static DWORD format_args(char *buffer, DWORD size, const char *format, ...) {
	DWORD result;
	va_list args;

	va_start(args, format);
	result = FormatMessageA(FORMAT_MESSAGE_FROM_STRING, format, 0, 0, buffer, size, &args);
	va_end(args);
	return result;
}

int main(void) {
	char buffer[128];
	char *allocated = NULL;
	wchar_t wide[] = L"wide";
	ULONG_PTR arguments[2];
	DWORD result;

	arguments[0] = (ULONG_PTR) "world";
	arguments[1] = 42;
	result = FormatMessageA(FORMAT_MESSAGE_FROM_STRING | FORMAT_MESSAGE_ARGUMENT_ARRAY, "Hello %1!s!, %2!u!%%%n", 0, 0,
							buffer, sizeof(buffer), (va_list *)arguments);
	TEST_CHECK_EQ(18, result);
	TEST_CHECK_STR_EQ("Hello world, 42%\r\n", buffer);

	result = format_args(buffer, sizeof(buffer), "%1!s! %2!08X!", "value", 0x2a);
	TEST_CHECK_EQ(14, result);
	TEST_CHECK_STR_EQ("value 0000002A", buffer);

	arguments[0] = (ULONG_PTR)wide;
	result = FormatMessageA(FORMAT_MESSAGE_FROM_STRING | FORMAT_MESSAGE_ARGUMENT_ARRAY, "%1!S!", 0, 0, buffer,
							sizeof(buffer), (va_list *)arguments);
	TEST_CHECK_EQ(4, result);
	TEST_CHECK_STR_EQ("wide", buffer);

	result = FormatMessageA(FORMAT_MESSAGE_FROM_STRING | FORMAT_MESSAGE_IGNORE_INSERTS, "Keep %1!s!%%%n", 0, 0, buffer,
							sizeof(buffer), NULL);
	TEST_CHECK_EQ(14, result);
	TEST_CHECK_STR_EQ("Keep %1!s!%%\r\n", buffer);

	result = FormatMessageA(FORMAT_MESSAGE_FROM_STRING | FORMAT_MESSAGE_ALLOCATE_BUFFER, "allocated", 0, 0,
							(char *)&allocated, 0, NULL);
	TEST_CHECK_EQ(9, result);
	TEST_CHECK(allocated != NULL);
	TEST_CHECK_STR_EQ("allocated", allocated);
	TEST_CHECK(LocalFree(allocated) == NULL);

	SetLastError(0xdeadbeef);
	result = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, ERROR_FILE_NOT_FOUND, 0,
							buffer, sizeof(buffer), NULL);
	TEST_CHECK_EQ(17, result);
	TEST_CHECK_STR_EQ("File not found.\r\n", buffer);
	TEST_CHECK_EQ(0xdeadbeef, GetLastError());

	SetLastError(0);
	result = FormatMessageA(FORMAT_MESSAGE_FROM_STRING, "too long", 0, 0, buffer, 4, NULL);
	TEST_CHECK_EQ(0, result);
	TEST_CHECK_EQ(ERROR_INSUFFICIENT_BUFFER, GetLastError());

	SetLastError(0);
	result = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, 0xfefefefe, 0, buffer,
							sizeof(buffer), NULL);
	TEST_CHECK_EQ(0, result);
	TEST_CHECK_EQ(ERROR_MR_MID_NOT_FOUND, GetLastError());

	return 0;
}
