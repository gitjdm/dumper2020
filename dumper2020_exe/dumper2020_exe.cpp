#include "../dumper2020/dumper2020.h"

int main()
{
	// Dump to "log.txt" in the current directory
	WCHAR wcDumpPath[MAX_PATH];
	GetCurrentDirectory(MAX_PATH, &wcDumpPath[0]);
	wcscat_s(wcDumpPath, MAX_PATH, L"\\log.txt");

	return Dump(wcDumpPath);
}