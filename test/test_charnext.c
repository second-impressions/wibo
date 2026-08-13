#include <windows.h>

#include "test_assert.h"

int main(void) {
	char ascii[] = "ab";
	char empty[] = "";
	char danglingLead[] = {(char)0x81, '\0'};

	TEST_CHECK(CharNextA(ascii) == ascii + 1);
	TEST_CHECK(CharNextA(ascii + 1) == ascii + 2);
	TEST_CHECK(CharNextA(ascii + 2) == ascii + 2);
	TEST_CHECK(CharNextA(empty) == empty);

	/* A lead byte without a following trail byte advances only to the NUL. */
	TEST_CHECK(CharNextExA(932, danglingLead, 0) == danglingLead + 1);

	return 0;
}
