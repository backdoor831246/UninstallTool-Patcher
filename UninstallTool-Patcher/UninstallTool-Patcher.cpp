#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdint>


// mov eax, 3 ; B8 03 00 00 00
// ret ; C3


// ImageBase binary (из IDA: Edit -> Segments -> Rebase)
static const uint64_t IMAGE_BASE = 0x140000000ULL;

// VA sub_140009A70
static const uint64_t TARGET_VA = 0x140009A70ULL;

// RVA = VA - ImageBase
static const uint32_t TARGET_RVA = (uint32_t)(TARGET_VA - IMAGE_BASE);

// ( mov eax, 3 ; ret)
static const uint8_t PATCH_BYTES[] = { 0xB8, 0x03, 0x00, 0x00, 0x00, 0xC3 };
static const size_t  PATCH_SIZE = sizeof(PATCH_BYTES);

static const char    MARKER_STR[] = "IsRegistered";
static const size_t  MARKER_LEN = sizeof(MARKER_STR) - 1; // 12 byte

#pragma pack(push, 1)
struct PeHeaders {
	IMAGE_DOS_HEADER       dos;
	// dos.e_lfanew -> IMAGE_NT_HEADERS64
};
#pragma pack(pop)

uint32_t RvaToFileOffset(const std::vector<uint8_t>& buf, uint32_t rva) {
	auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(buf.data());
	auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(buf.data() + dos->e_lfanew);

	uint16_t numSections = nt->FileHeader.NumberOfSections;
	auto* sec = IMAGE_FIRST_SECTION(nt);

	for (uint16_t i = 0; i < numSections; i++) {
		uint32_t secVA = sec[i].VirtualAddress;
		uint32_t secRaw = sec[i].SizeOfRawData;
		uint32_t secOff = sec[i].PointerToRawData;

		if (rva >= secVA && rva < secVA + secRaw) {
			return secOff + (rva - secVA);
		}
	}
	return 0; // :((((((((
}
size_t FindPattern(const std::vector<uint8_t>& buf,
	const uint8_t* pattern, size_t patLen) {
	for (size_t i = 0; i + patLen <= buf.size(); i++) {
		if (memcmp(buf.data() + i, pattern, patLen) == 0)
			return i;
	}
	return (size_t)-1;
}

int main(int argc, char* argv[]) {
	if (argc < 2) {
		std::cerr << "Usage: UninstallTool-Patcher.exe <target.exe>\n";
		return 1;
	}

	const std::string path = argv[1];

	std::ifstream fin(path, std::ios::binary);
	if (!fin) {
		std::cerr << "[!] Cannot open file: " << path << "\n";
		return 1;
	}
	std::vector<uint8_t> buf(
		(std::istreambuf_iterator<char>(fin)),
		std::istreambuf_iterator<char>());
	fin.close();
	std::cout << "[*] File loaded: " << buf.size() << " bytes\n";

	if (buf.size() < sizeof(IMAGE_DOS_HEADER) ||
		*reinterpret_cast<uint16_t*>(buf.data()) != IMAGE_DOS_SIGNATURE) {
		std::cerr << "[!] Not a valid PE file\n";
		return 1;
	}

	size_t markerOff = FindPattern(buf,
		reinterpret_cast<const uint8_t*>(MARKER_STR), MARKER_LEN);
	if (markerOff == (size_t)-1) {
		std::cerr << "[!] Marker string 'IsRegistered' not found — wrong binary?\n";
		return 1;
	}
	std::cout << "[+] Marker 'IsRegistered' found at file offset 0x"
		<< std::hex << markerOff << std::dec << "\n";

	uint32_t fileOff = RvaToFileOffset(buf, TARGET_RVA);
	if (fileOff == 0) {
		std::cerr << "[!] RVA 0x" << std::hex << TARGET_RVA
			<< " not found in any section\n";
		return 1;
	}
	std::cout << "[+] sub_140009A70 file offset: 0x"
		<< std::hex << fileOff << std::dec << "\n";

	if (fileOff + PATCH_SIZE > buf.size()) {
		std::cerr << "[!] Patch would go out of bounds\n";
		return 1;
	}

	std::cout << "[*] Original bytes: ";
	for (size_t i = 0; i < PATCH_SIZE; i++)
		printf("%02X ", buf[fileOff + i]);
	printf("\n");

	memcpy(buf.data() + fileOff, PATCH_BYTES, PATCH_SIZE);

	std::cout << "[+] Patch applied:  ";
	for (size_t i = 0; i < PATCH_SIZE; i++)
		printf("%02X ", PATCH_BYTES[i]);
	printf("\n");

	std::string outPath = path + ".patched.exe";
	std::ofstream fout(outPath, std::ios::binary);
	if (!fout) {
		std::cerr << "[!] Cannot write output: " << outPath << "\n";
		return 1;
	}
	fout.write(reinterpret_cast<char*>(buf.data()), buf.size());
	fout.close();

	std::cout << "[+] Patched file saved: " << outPath << "\n";
	std::cout << "[+] Done! IsRegistered will now always return 3.\n";
	return 0;
}