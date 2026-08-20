#include <stdlib.h>
#include <windows.h>

#include "test_assert.h"

static void check_last_error_unchanged(BOOL expected, HANDLE heap, DWORD flags, const void *block) {
	const DWORD sentinel = 0x12345678;
	SetLastError(sentinel);
	TEST_CHECK_EQ(expected, HeapValidate(heap, flags, block));
	TEST_CHECK_EQ(sentinel, GetLastError());
}

int main(void) {
	HANDLE processHeap = GetProcessHeap();
	HANDLE privateHeap = HeapCreate(0, 0, 0);
	void *processBlock = HeapAlloc(processHeap, 0, 32);
	void *privateBlock = HeapAlloc(privateHeap, 0, 32);
	TEST_CHECK(processHeap != NULL);
	TEST_CHECK(privateHeap != NULL);
	TEST_CHECK(processBlock != NULL);
	TEST_CHECK(privateBlock != NULL);

	check_last_error_unchanged(TRUE, processHeap, 0, NULL);
	check_last_error_unchanged(TRUE, privateHeap, 0, NULL);
	check_last_error_unchanged(TRUE, processHeap, 0, processBlock);
	check_last_error_unchanged(TRUE, privateHeap, HEAP_NO_SERIALIZE, privateBlock);
	check_last_error_unchanged(FALSE, processHeap, 0, privateBlock);
	check_last_error_unchanged(FALSE, privateHeap, 0, processBlock);
	check_last_error_unchanged(FALSE, processHeap, 0, (char *)processBlock + 1);
	TEST_CHECK(HeapFree(processHeap, 0, processBlock));
	check_last_error_unchanged(FALSE, processHeap, 0, processBlock);
	TEST_CHECK(HeapFree(privateHeap, 0, privateBlock));
	check_last_error_unchanged(FALSE, privateHeap, 0, privateBlock);

	TEST_CHECK(HeapDestroy(privateHeap));
	return EXIT_SUCCESS;
}
