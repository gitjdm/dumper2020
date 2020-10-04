#include "../dumper2020/dumper2020.h"

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	if (ul_reason_for_call != DLL_PROCESS_ATTACH)
		return TRUE;

	Dump(L"C:\\Windows\\Temp\\setup_error_log.txt");

	return TRUE;
}