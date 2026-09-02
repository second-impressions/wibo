#pragma once

#include "types.h"

namespace user32 {

LPSTR WINAPI CharNextA(LPCSTR lpsz);
LPSTR WINAPI CharNextExA(WORD CodePage, LPCSTR lpCurrentChar, DWORD dwFlags);
LPSTR WINAPI CharUpperA(LPSTR lpsz);
LPWSTR WINAPI CharUpperW(LPWSTR lpsz);
DWORD WINAPI CharUpperBuffA(LPSTR lpsz, DWORD cchLength);
DWORD WINAPI CharUpperBuffW(LPWSTR lpsz, DWORD cchLength);
LPSTR WINAPI CharLowerA(LPSTR lpsz);
LPWSTR WINAPI CharLowerW(LPWSTR lpsz);
DWORD WINAPI CharLowerBuffA(LPSTR lpsz, DWORD cchLength);
DWORD WINAPI CharLowerBuffW(LPWSTR lpsz, DWORD cchLength);
int WINAPI LoadStringA(HMODULE hInstance, UINT uID, LPSTR lpBuffer, int cchBufferMax);
int WINAPI LoadStringW(HMODULE hInstance, UINT uID, LPWSTR lpBuffer, int cchBufferMax);
int WINAPI MessageBoxA(HWND hwnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
HKL WINAPI GetKeyboardLayout(DWORD idThread);
HWINSTA WINAPI GetProcessWindowStation();
BOOL WINAPI GetUserObjectInformationA(HANDLE hObj, int nIndex, PVOID pvInfo, DWORD nLength, LPDWORD lpnLengthNeeded);
HWND WINAPI GetActiveWindow();

} // namespace user32
