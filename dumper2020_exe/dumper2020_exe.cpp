#include "../dumper2020/dumper2020.h"

int main()
{
	// Dump to "log.txt" in the current directory
	WCHAR dumpPath[MAX_PATH];
	GetCurrentDirectory(MAX_PATH, &dumpPath[0]);
	wcscat_s(dumpPath, MAX_PATH, L"\\log.txt");

	return Dump((LPWSTR)dumpPath);
}
