// PackerTestApp.cpp : Generic testing PE for packers
// by mos9527, 2022
/* References:
	https://learn.microsoft.com/en-us/cpp/parallel/multithreading-with-c-and-win32
	https://bidouillesecurity.com/tutorial-writing-a-pe-packer-part-1/
	https://github.com/jeremybeaume/packer-tutorial
*/
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <Psapi.h>
#include <stdio.h>

#define EXIT_OK 0
#define EXIT_INVALID_FS 1
#define EXIT_INVALID_TLS 2
#define EXIT_INVALID_OVERLAY 3
const char* MAGIC = "El Psy Kongroo.";

__declspec(thread) int tls_value = 0;
int WINAPI thread_job(int no) {
	printf("TLS run #%d: tls_value before thread job:%d\n", no, tls_value);
	if (tls_value != 0) {
		printf(">>> Bad TLS initial value. Early out.\n");
		ExitProcess(EXIT_INVALID_TLS);
	}
	tls_value = no;
	printf("TLS run #%d: tls_value after thread job:%d\n", no, tls_value);
	return 0;
}
int main()
{	
	printf("TLS - Thread Local Storage\n");
	for (int i = 1; i <= 2; i++) {
		HANDLE thread = _beginthread(thread_job, 0, i);
		WaitForSingleObject(thread, INFINITE);
	}
	printf(">>> TLS Checks OK.\n");
	HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);
	char BUFFER[1024] = { 0 };
	DWORD bytesRead;
	if (handle) {		
		printf("Win32 API Hook - CreateFile,ReadFile (README.txt)\n");
		HANDLE file = CreateFileA(
			"README.txt", GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
		);
		if (file == INVALID_HANDLE_VALUE) {
			printf("Cannot open file for reading!\n");
			ExitProcess(EXIT_INVALID_FS);
		}
		else {
			if (ReadFile(file, BUFFER, 1024, &bytesRead, NULL)) {				
				if (memcmp(BUFFER, MAGIC, strlen(MAGIC)) != 0) {
					printf(">>> Invalid README.txt content!\n");
					ExitProcess(EXIT_INVALID_FS);
				}
				else {
					printf(">>> README.txt content OK.\n");
				}
			}
		}
		printf("PE Modification - Sections\n");
		/** Parse header **/
		char* VA = (char*)GetModuleHandleA(NULL);
		IMAGE_DOS_HEADER* p_DOS_HDR = (IMAGE_DOS_HEADER*)VA;
		IMAGE_NT_HEADERS* p_NT_HDR = (IMAGE_NT_HEADERS*)(((char*)p_DOS_HDR) + p_DOS_HDR->e_lfanew);
		// Note: We’re manipulating pointers, so be very, very carefull with pointer arithmetic:
		// pointer + 1 actually adds size_of(type of the pointer), hence the cast in char*. Easy mistake to make here!
		IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*)(p_NT_HDR + 1);
		DWORD hdr_image_base = p_NT_HDR->OptionalHeader.ImageBase;
		DWORD size_of_image = p_NT_HDR->OptionalHeader.SizeOfImage;
		DWORD entry_point_RVA = p_NT_HDR->OptionalHeader.AddressOfEntryPoint;
		DWORD size_of_headers = p_NT_HDR->OptionalHeader.SizeOfHeaders;
		DWORD number_of_sections = p_NT_HDR->FileHeader.NumberOfSections;
		for (DWORD i = 0; i < number_of_sections; i++) {
			printf("%s	VA=0x%x RawPtr=0x%x RawSize=0x%x\n", sections[i].Name,sections[i].VirtualAddress,sections[i].PointerToRawData,sections[i].SizeOfRawData);
		}
		printf("Misc - Overlay\n");
		DWORD start_of_overlay = sections[number_of_sections - 1].PointerToRawData + sections[number_of_sections - 1].SizeOfRawData;
		// Overlays are not memory-mapped. Read them from the exe
		memset(BUFFER, 0, 1024);
		if (GetModuleFileNameA(NULL,BUFFER,1024)) {
			// GetProcessImageFileNameA gives us NT paths which we can only use by calling internal APIs
			printf("Name	%s\n", BUFFER);
			file = CreateFileA(BUFFER, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			if (file == INVALID_HANDLE_VALUE) {
				printf("Cannot open file for reading!\n");
			}
			else {
				if (SetFilePointer(file, LOWORD(start_of_overlay),0 , FILE_BEGIN)) {
					if (ReadFile(file, BUFFER, 1024, &bytesRead, NULL))
						if (memcmp(BUFFER, MAGIC, strlen(MAGIC)) != 0) {
							printf(">>> Invalid Overlay content!\n");
							ExitProcess(EXIT_INVALID_OVERLAY);
						}
						else {
							printf(">>> Overlay content OK. %s\n", BUFFER);
						}
				}
			}
		}
		else {
			printf("Cannot acquire filename for self!\n");
		}		
	}
	
return 0;		
}