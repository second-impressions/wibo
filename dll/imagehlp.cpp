#include "imagehlp.h"

#include "common.h"
#include "context.h"
#include "errors.h"
#include "files.h"
#include "kernel32/internal.h"
#include "modules.h"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <limits>
#include <string>
#include <vector>

namespace {

constexpr uint16_t kDosSignature = 0x5a4d;
constexpr uint32_t kPeSignature = 0x00004550;
constexpr uint16_t kPe32Magic = 0x10b;
constexpr uint16_t kImageFileLineNumsStripped = 0x0004;
constexpr uint16_t kImageFileDebugStripped = 0x0200;
constexpr uint32_t kImageScnCntCode = 0x00000020;
constexpr uint32_t kImageScnCntInitializedData = 0x00000040;
constexpr uint32_t kImageScnMemWrite = 0x80000000;
constexpr size_t kDirectoryBaseReloc = 5;
constexpr size_t kDirectoryDebug = 6;
constexpr uint16_t kRelocAbsolute = 0;
constexpr uint16_t kRelocHigh = 1;
constexpr uint16_t kRelocLow = 2;
constexpr uint16_t kRelocHighLow = 3;
constexpr uint16_t kRelocHighAdj = 4;
constexpr uint16_t kSeparateDebugSignature = 0x4944;
constexpr uint32_t kDebugTypeCodeView = 2;
constexpr ULONG kSplitSymbolsRemovePrivate = 0x1;
constexpr ULONG kSplitSymbolsExtractAll = 0x2;
constexpr ULONG kSplitSymbolsPathIsSrc = 0x4;

#pragma pack(push, 1)
struct CoffHeader {
	uint16_t machine;
	uint16_t numberOfSections;
	uint32_t timeDateStamp;
	uint32_t pointerToSymbolTable;
	uint32_t numberOfSymbols;
	uint16_t sizeOfOptionalHeader;
	uint16_t characteristics;
};

struct DataDirectory {
	uint32_t virtualAddress;
	uint32_t size;
};

struct OptionalHeader32 {
	uint16_t magic;
	uint8_t majorLinkerVersion;
	uint8_t minorLinkerVersion;
	uint32_t sizeOfCode;
	uint32_t sizeOfInitializedData;
	uint32_t sizeOfUninitializedData;
	uint32_t addressOfEntryPoint;
	uint32_t baseOfCode;
	uint32_t baseOfData;
	uint32_t imageBase;
	uint32_t sectionAlignment;
	uint32_t fileAlignment;
	uint16_t majorOperatingSystemVersion;
	uint16_t minorOperatingSystemVersion;
	uint16_t majorImageVersion;
	uint16_t minorImageVersion;
	uint16_t majorSubsystemVersion;
	uint16_t minorSubsystemVersion;
	uint32_t win32VersionValue;
	uint32_t sizeOfImage;
	uint32_t sizeOfHeaders;
	uint32_t checkSum;
	uint16_t subsystem;
	uint16_t dllCharacteristics;
	uint32_t sizeOfStackReserve;
	uint32_t sizeOfStackCommit;
	uint32_t sizeOfHeapReserve;
	uint32_t sizeOfHeapCommit;
	uint32_t loaderFlags;
	uint32_t numberOfRvaAndSizes;
	DataDirectory directories[16];
};

struct SectionHeader {
	char name[8];
	uint32_t virtualSize;
	uint32_t virtualAddress;
	uint32_t sizeOfRawData;
	uint32_t pointerToRawData;
	uint32_t pointerToRelocations;
	uint32_t pointerToLinenumbers;
	uint16_t numberOfRelocations;
	uint16_t numberOfLinenumbers;
	uint32_t characteristics;
};

struct DebugDirectory {
	uint32_t characteristics;
	uint32_t timeDateStamp;
	uint16_t majorVersion;
	uint16_t minorVersion;
	uint32_t type;
	uint32_t sizeOfData;
	uint32_t addressOfRawData;
	uint32_t pointerToRawData;
};

struct SeparateDebugHeader {
	uint16_t signature;
	uint16_t flags;
	uint16_t machine;
	uint16_t characteristics;
	uint32_t timeDateStamp;
	uint32_t checkSum;
	uint32_t imageBase;
	uint32_t sizeOfImage;
	uint32_t numberOfSections;
	uint32_t exportedNamesSize;
	uint32_t debugDirectorySize;
	uint32_t sectionAlignment;
	uint32_t reserved[2];
};

struct BaseRelocationBlock {
	uint32_t virtualAddress;
	uint32_t sizeOfBlock;
};
#pragma pack(pop)

struct PeImage {
	std::vector<uint8_t> bytes;
	size_t peOffset = 0;
	CoffHeader *coff = nullptr;
	OptionalHeader32 *optional = nullptr;
	SectionHeader *sections = nullptr;
};

template <typename T> bool rangeFits(size_t offset, size_t count, const std::vector<uint8_t> &bytes) {
	return count <= (std::numeric_limits<size_t>::max() - offset) / sizeof(T) &&
		   offset + count * sizeof(T) <= bytes.size();
}

bool loadFile(const std::filesystem::path &path, std::vector<uint8_t> &bytes) {
	FILE *file = std::fopen(path.string().c_str(), "rb");
	if (!file)
		return false;
	if (std::fseek(file, 0, SEEK_END) != 0) {
		std::fclose(file);
		return false;
	}
	long length = std::ftell(file);
	if (length < 0 || std::fseek(file, 0, SEEK_SET) != 0) {
		std::fclose(file);
		return false;
	}
	bytes.resize(static_cast<size_t>(length));
	bool ok = bytes.empty() || std::fread(bytes.data(), 1, bytes.size(), file) == bytes.size();
	std::fclose(file);
	return ok;
}

bool writeFile(const std::filesystem::path &path, const std::vector<uint8_t> &bytes) {
	FILE *file = std::fopen(path.string().c_str(), "wb");
	if (!file)
		return false;
	bool ok = bytes.empty() || std::fwrite(bytes.data(), 1, bytes.size(), file) == bytes.size();
	ok = std::fclose(file) == 0 && ok;
	return ok;
}

bool parsePe(PeImage &image) {
	if (!rangeFits<uint16_t>(0, 1, image.bytes) || *reinterpret_cast<uint16_t *>(image.bytes.data()) != kDosSignature ||
		!rangeFits<uint32_t>(0x3c, 1, image.bytes))
		return false;
	image.peOffset = *reinterpret_cast<uint32_t *>(image.bytes.data() + 0x3c);
	if (!rangeFits<uint32_t>(image.peOffset, 1, image.bytes) ||
		*reinterpret_cast<uint32_t *>(image.bytes.data() + image.peOffset) != kPeSignature ||
		!rangeFits<CoffHeader>(image.peOffset + 4, 1, image.bytes))
		return false;
	image.coff = reinterpret_cast<CoffHeader *>(image.bytes.data() + image.peOffset + 4);
	size_t optionalOffset = image.peOffset + 4 + sizeof(CoffHeader);
	if (image.coff->sizeOfOptionalHeader < offsetof(OptionalHeader32, directories) ||
		!rangeFits<uint8_t>(optionalOffset, image.coff->sizeOfOptionalHeader, image.bytes))
		return false;
	image.optional = reinterpret_cast<OptionalHeader32 *>(image.bytes.data() + optionalOffset);
	if (image.optional->magic != kPe32Magic)
		return false;
	size_t sectionOffset = optionalOffset + image.coff->sizeOfOptionalHeader;
	if (!rangeFits<SectionHeader>(sectionOffset, image.coff->numberOfSections, image.bytes))
		return false;
	image.sections = reinterpret_cast<SectionHeader *>(image.bytes.data() + sectionOffset);
	return true;
}

size_t rvaToOffset(const PeImage &image, uint32_t rva, size_t size = 1) {
	if (rva < image.optional->sizeOfHeaders && rva <= image.bytes.size() && size <= image.bytes.size() - rva)
		return rva;
	for (uint16_t i = 0; i < image.coff->numberOfSections; ++i) {
		const SectionHeader &section = image.sections[i];
		uint32_t span = std::max(section.virtualSize, section.sizeOfRawData);
		if (rva < section.virtualAddress || rva - section.virtualAddress >= span)
			continue;
		size_t offset = section.pointerToRawData + static_cast<size_t>(rva - section.virtualAddress);
		if (offset <= image.bytes.size() && size <= image.bytes.size() - offset)
			return offset;
	}
	return std::numeric_limits<size_t>::max();
}

SectionHeader *sectionForRva(PeImage &image, uint32_t rva) {
	for (uint16_t i = 0; i < image.coff->numberOfSections; ++i) {
		SectionHeader &section = image.sections[i];
		uint32_t span = std::max(section.virtualSize, section.sizeOfRawData);
		if (rva >= section.virtualAddress && rva - section.virtualAddress < span)
			return &section;
	}
	return nullptr;
}

bool hasDirectory(const PeImage &image, size_t index) {
	return image.optional->numberOfRvaAndSizes > index &&
		   offsetof(OptionalHeader32, directories) + (index + 1) * sizeof(DataDirectory) <=
			   image.coff->sizeOfOptionalHeader;
}

size_t sectionDataEnd(const PeImage &image) {
	size_t end = image.optional->sizeOfHeaders;
	for (uint16_t i = 0; i < image.coff->numberOfSections; ++i) {
		const SectionHeader &section = image.sections[i];
		if (section.pointerToRawData <= std::numeric_limits<size_t>::max() - section.sizeOfRawData)
			end = std::max(end, static_cast<size_t>(section.pointerToRawData) + section.sizeOfRawData);
	}
	return std::min(end, image.bytes.size());
}

uint32_t peChecksum(const PeImage &image) {
	size_t checksumOffset = reinterpret_cast<const uint8_t *>(&image.optional->checkSum) - image.bytes.data();
	uint64_t sum = 0;
	for (size_t offset = 0; offset < image.bytes.size(); offset += 2) {
		if (offset == checksumOffset || offset == checksumOffset + 2)
			continue;
		uint16_t word = image.bytes[offset];
		if (offset + 1 < image.bytes.size())
			word |= static_cast<uint16_t>(image.bytes[offset + 1]) << 8;
		sum += word;
		sum = (sum & 0xffff) + (sum >> 16);
	}
	sum = (sum & 0xffff) + (sum >> 16);
	sum += image.bytes.size();
	return static_cast<uint32_t>(sum);
}

bool appendBytes(std::vector<uint8_t> &output, const void *data, size_t size) {
	if (size > std::numeric_limits<size_t>::max() - output.size())
		return false;
	const auto *begin = static_cast<const uint8_t *>(data);
	output.insert(output.end(), begin, begin + size);
	return true;
}

bool extractDebugFile(const PeImage &image, const std::filesystem::path &debugPath, ULONG flags) {
	SeparateDebugHeader header{};
	header.signature = kSeparateDebugSignature;
	header.machine = image.coff->machine;
	header.characteristics = image.coff->characteristics;
	header.timeDateStamp = image.coff->timeDateStamp;
	header.checkSum = image.optional->checkSum;
	header.imageBase = image.optional->imageBase;
	header.sizeOfImage = image.optional->sizeOfImage;
	header.numberOfSections = image.coff->numberOfSections;
	header.sectionAlignment = image.optional->sectionAlignment;

	std::vector<DebugDirectory> directories;
	if (hasDirectory(image, kDirectoryDebug)) {
		const DataDirectory &debug = image.optional->directories[kDirectoryDebug];
		size_t offset = rvaToOffset(image, debug.virtualAddress, debug.size);
		if (offset != std::numeric_limits<size_t>::max()) {
			size_t count = debug.size / sizeof(DebugDirectory);
			const auto *entries = reinterpret_cast<const DebugDirectory *>(image.bytes.data() + offset);
			for (size_t i = 0; i < count; ++i) {
				const DebugDirectory &entry = entries[i];
				bool embeddedCodeView = false;
				if ((flags & kSplitSymbolsRemovePrivate) && !(flags & kSplitSymbolsExtractAll) &&
					entry.type == kDebugTypeCodeView && entry.sizeOfData >= 4 &&
					entry.pointerToRawData <= image.bytes.size() &&
					entry.sizeOfData <= image.bytes.size() - entry.pointerToRawData) {
					const uint8_t *magic = image.bytes.data() + entry.pointerToRawData;
					embeddedCodeView = std::memcmp(magic, "NB10", 4) != 0 && std::memcmp(magic, "RSDS", 4) != 0;
				}
				if (!embeddedCodeView)
					directories.push_back(entry);
			}
		}
	}
	header.debugDirectorySize = static_cast<uint32_t>(directories.size() * sizeof(DebugDirectory));

	std::vector<uint8_t> output;
	if (!appendBytes(output, &header, sizeof(header)) ||
		!appendBytes(output, image.sections, image.coff->numberOfSections * sizeof(SectionHeader)))
		return false;
	size_t directoryOffset = output.size();
	output.resize(output.size() + directories.size() * sizeof(DebugDirectory), 0);

	for (size_t i = 0; i < directories.size(); ++i) {
		DebugDirectory copy = directories[i];
		copy.addressOfRawData = 0;
		if (copy.sizeOfData && copy.pointerToRawData <= image.bytes.size() &&
			copy.sizeOfData <= image.bytes.size() - copy.pointerToRawData) {
			copy.pointerToRawData = static_cast<uint32_t>(output.size());
			if (!appendBytes(output, image.bytes.data() + directories[i].pointerToRawData, copy.sizeOfData))
				return false;
		} else {
			copy.pointerToRawData = 0;
			copy.sizeOfData = 0;
		}
		std::memcpy(output.data() + directoryOffset + i * sizeof(DebugDirectory), &copy, sizeof(copy));
	}

	std::error_code ec;
	std::filesystem::create_directories(debugPath.parent_path(), ec);
	if (ec)
		return false;
	return writeFile(debugPath, output);
}

bool applyRelocations(PeImage &image, int64_t delta) {
	if (delta == 0)
		return true;
	if (!hasDirectory(image, kDirectoryBaseReloc))
		return false;
	const DataDirectory &relocations = image.optional->directories[kDirectoryBaseReloc];
	if (!relocations.virtualAddress || !relocations.size)
		return false;
	size_t tableOffset = rvaToOffset(image, relocations.virtualAddress, relocations.size);
	if (tableOffset == std::numeric_limits<size_t>::max())
		return false;
	size_t cursor = tableOffset;
	size_t end = tableOffset + relocations.size;
	while (cursor + sizeof(BaseRelocationBlock) <= end) {
		const auto *block = reinterpret_cast<const BaseRelocationBlock *>(image.bytes.data() + cursor);
		if (block->sizeOfBlock < sizeof(BaseRelocationBlock) || block->sizeOfBlock > end - cursor)
			return false;
		size_t count = (block->sizeOfBlock - sizeof(BaseRelocationBlock)) / sizeof(uint16_t);
		const auto *entries = reinterpret_cast<const uint16_t *>(image.bytes.data() + cursor + sizeof(*block));
		for (size_t i = 0; i < count; ++i) {
			uint16_t type = entries[i] >> 12;
			uint32_t targetRva = block->virtualAddress + (entries[i] & 0xfff);
			if (type == kRelocAbsolute)
				continue;
			if (type == kRelocHighLow) {
				size_t offset = rvaToOffset(image, targetRva, sizeof(uint32_t));
				if (offset == std::numeric_limits<size_t>::max())
					return false;
				auto *value = reinterpret_cast<uint32_t *>(image.bytes.data() + offset);
				*value += static_cast<uint32_t>(delta);
			} else if (type == kRelocHigh || type == kRelocLow) {
				size_t offset = rvaToOffset(image, targetRva, sizeof(uint16_t));
				if (offset == std::numeric_limits<size_t>::max())
					return false;
				auto *value = reinterpret_cast<uint16_t *>(image.bytes.data() + offset);
				*value += static_cast<uint16_t>(type == kRelocHigh ? delta >> 16 : delta);
			} else if (type == kRelocHighAdj) {
				if (++i >= count)
					return false;
				size_t offset = rvaToOffset(image, targetRva, sizeof(uint16_t));
				if (offset == std::numeric_limits<size_t>::max())
					return false;
				auto *value = reinterpret_cast<uint16_t *>(image.bytes.data() + offset);
				int64_t combined = (static_cast<int64_t>(static_cast<int16_t>(*value)) << 16) +
								   static_cast<int16_t>(entries[i]) + delta + 0x8000;
				*value = static_cast<uint16_t>(combined >> 16);
			} else {
				return false;
			}
		}
		cursor += block->sizeOfBlock;
	}
	return true;
}

void setIoError() { kernel32::setLastError(wibo::winErrorFromErrno(errno)); }

} // namespace

namespace imagehlp {

BOOL WINAPI SplitSymbols(LPSTR imageName, LPCSTR symbolsPath, LPSTR symbolFilePath, ULONG flags) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("SplitSymbols(%s, %s, %p, %#x)\n", imageName ? imageName : "(null)", symbolsPath ? symbolsPath : "(null)",
			  symbolFilePath, flags);
	if (!imageName || (flags & ~(kSplitSymbolsRemovePrivate | kSplitSymbolsExtractAll | kSplitSymbolsPathIsSrc))) {
		kernel32::setLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	std::filesystem::path imagePath = files::pathFromWindows(imageName);
	PeImage image;
	if (!loadFile(imagePath, image.bytes)) {
		setIoError();
		return FALSE;
	}
	if (!parsePe(image)) {
		kernel32::setLastError(ERROR_BAD_EXE_FORMAT);
		return FALSE;
	}

	std::filesystem::path debugPath;
	if (symbolsPath && *symbolsPath) {
		debugPath = files::pathFromWindows(symbolsPath);
		std::string extension = imagePath.extension().string();
		if (!extension.empty() && extension[0] == '.')
			extension.erase(0, 1);
		std::transform(extension.begin(), extension.end(), extension.begin(),
					   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
		if (!extension.empty())
			debugPath /= extension;
		debugPath /= imagePath.stem().string() + ".dbg";
	} else {
		debugPath = imagePath.parent_path() / (imagePath.stem().string() + ".dbg");
	}

	if (!extractDebugFile(image, debugPath, flags)) {
		setIoError();
		return FALSE;
	}

	image.coff->characteristics |= kImageFileLineNumsStripped | kImageFileDebugStripped;
	if ((flags & kSplitSymbolsExtractAll) && hasDirectory(image, kDirectoryDebug))
		image.optional->directories[kDirectoryDebug] = {};
	size_t end = sectionDataEnd(image);
	image.bytes.resize(end);
	if (!writeFile(imagePath, image.bytes)) {
		setIoError();
		return FALSE;
	}
	if (symbolFilePath)
		std::strcpy(symbolFilePath, files::pathToWindows(debugPath).c_str());
	return TRUE;
}

BOOL WINAPI ReBaseImage(LPCSTR currentImageName, LPCSTR symbolPath, BOOL reBase, BOOL rebaseSystemFileOk,
						BOOL goingDown, ULONG checkImageSize, ULONG *oldImageSize, ULONG_PTR *oldImageBase,
						ULONG *newImageSize, ULONG_PTR *newImageBase, ULONG timeStamp) {
	HOST_CONTEXT_GUARD();
	DEBUG_LOG("ReBaseImage(%s, %s, %d, %d, %d, %#x, %p, %p, %p, %p=%#x, %#x)\n",
			  currentImageName ? currentImageName : "(null)", symbolPath ? symbolPath : "(null)", reBase,
			  rebaseSystemFileOk, goingDown, checkImageSize, oldImageSize, oldImageBase, newImageSize, newImageBase,
			  newImageBase ? static_cast<unsigned>(*newImageBase) : 0, timeStamp);
	(void)symbolPath;
	(void)rebaseSystemFileOk;
	if (!currentImageName || !newImageBase) {
		kernel32::setLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	std::filesystem::path imagePath = files::pathFromWindows(currentImageName);
	PeImage image;
	if (!loadFile(imagePath, image.bytes)) {
		setIoError();
		return FALSE;
	}
	if (!parsePe(image)) {
		kernel32::setLastError(ERROR_BAD_EXE_FORMAT);
		return FALSE;
	}

	uint32_t originalSize = image.optional->sizeOfImage;
	uint32_t originalBase = image.optional->imageBase;
	if (oldImageSize)
		*oldImageSize = originalSize;
	if (oldImageBase)
		*oldImageBase = originalBase;
	if (checkImageSize && originalSize > checkImageSize) {
		kernel32::setLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	uint64_t alignedBase =
		goingDown ? (*newImageBase & ~UINT64_C(0xffff)) : ((*newImageBase + 0xffff) & ~UINT64_C(0xffff));
	if (alignedBase > std::numeric_limits<uint32_t>::max()) {
		kernel32::setLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	uint32_t targetBase = static_cast<uint32_t>(alignedBase);
	if (reBase && !applyRelocations(image, static_cast<int64_t>(targetBase) - originalBase)) {
		kernel32::setLastError(ERROR_BAD_EXE_FORMAT);
		return FALSE;
	}
	if (reBase)
		image.optional->imageBase = targetBase;

	image.coff->timeDateStamp = timeStamp ? timeStamp : image.coff->timeDateStamp + 1;
	image.optional->sizeOfInitializedData = 0;
	image.optional->baseOfData = 0;
	for (uint16_t i = 0; i < image.coff->numberOfSections; ++i) {
		SectionHeader &section = image.sections[i];
		if (section.characteristics & kImageScnCntInitializedData)
			image.optional->sizeOfInitializedData += section.sizeOfRawData;
		if (!image.optional->baseOfData && (section.characteristics & kImageScnMemWrite) &&
			!(section.characteristics & kImageScnCntCode))
			image.optional->baseOfData = section.virtualAddress;
	}
	if (hasDirectory(image, kDirectoryBaseReloc)) {
		DataDirectory &relocations = image.optional->directories[kDirectoryBaseReloc];
		if (SectionHeader *section = sectionForRva(image, relocations.virtualAddress))
			relocations.size = section->virtualSize;
	}
	image.optional->checkSum = 0;
	image.optional->checkSum = peChecksum(image);
	if (!writeFile(imagePath, image.bytes)) {
		setIoError();
		return FALSE;
	}
	if (newImageSize)
		*newImageSize = image.optional->sizeOfImage;
	*newImageBase = targetBase;
	return TRUE;
}

} // namespace imagehlp

#include "imagehlp_trampolines.h"

extern const wibo::ModuleStub lib_imagehlp = {
	(const char *[]){
		"imagehlp",
		nullptr,
	},
	imagehlpThunkByName,
	nullptr,
};
