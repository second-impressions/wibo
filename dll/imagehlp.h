#pragma once

#include "types.h"

namespace imagehlp {

BOOL WINAPI SplitSymbols(LPSTR imageName, LPCSTR symbolsPath, LPSTR symbolFilePath, ULONG flags);
BOOL WINAPI ReBaseImage(LPCSTR currentImageName, LPCSTR symbolPath, BOOL reBase, BOOL rebaseSystemFileOk,
						BOOL goingDown, ULONG checkImageSize, ULONG *oldImageSize, ULONG_PTR *oldImageBase,
						ULONG *newImageSize, ULONG_PTR *newImageBase, ULONG timeStamp);

} // namespace imagehlp
