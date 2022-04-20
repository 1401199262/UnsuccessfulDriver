#include "globals.h"
#include "Utils.h"
#include "inlineUtils.h"

DECLSPEC_NOINLINE int FixRelatives(PVOID Func, SIZE_T size, PVOID FunList)
{
	int FixedCount = 0;
	//防止越界 如 0x1000 的8字节会读到 0x1007
	for (SIZE_T i = 0; i < size-sizeof(DWORD64); i++)
	{
		if (*(ULONG64*)((DWORD64)Func + i) - MAGICNUMBER < 0x10000 &&
			(LONG64)(*(ULONG64*)((DWORD64)Func + i) - MAGICNUMBER) >= 0)
		{
			//__debugbreak();
			FixedCount++;
			auto offs = ((*(DWORD64*)((DWORD64)Func + i)) - MAGICNUMBER);
			auto changedvalue = ((DWORD64)FunList + offs);
			*(DWORD64*)((DWORD64)Func + i) = changedvalue;
		}
	}
	return FixedCount;
}

DECLSPEC_NOINLINE INT64 NTAPI EDDHookProc(PVOID A1, PINT64 A2) {
	if (g_Fun->ExGetPreviousMode() != UserMode
		|| A1 == nullptr
		|| !inlineUtils::ProbeUserAddress(A1, sizeof(g_Fun->gCommunicationData), sizeof(DWORD))
		|| !inlineUtils::MMCopy(&g_Fun->gCommunicationData, A1, sizeof(CommunicationData))
		|| g_Fun->gCommunicationData.Magic != 0x999) 
	{
		g_Fun->DbgPrintEx(0, 0, g_Fun->Str_DoNormalEDD);

		// NtConvertBetweenAuxiliaryCounterAndPerformanceCounter() was not called by our usermode client
		// Call the original EnumerateDebuggingDevices() for whoever called

		return g_Fun->EDDOriginal(A1, A2);
	}

	InterlockedExchangePointer((PVOID*)g_Fun->pEDD, (PVOID)g_Fun->EDDOriginal);
	

	if (NT_SUCCESS(g_Fun->PsLookupProcessByProcessId((HANDLE)g_Fun->gCommunicationData.ProcessId,
		&g_Fun->gProcess)))
	{
		while (1)
		{
			if (*(DWORD*)((BYTE*)g_Fun->gProcess + g_Fun->ActiveThreadsOffset) == 1) {
				// We're the only active thread - the client must be trying to terminate
				g_Fun->DbgPrintEx(0, 0, g_Fun->Str_CloseCommunication, 1);
				g_Fun->ObfDereferenceObject(g_Fun->gProcess);
				return 1;
			}

			DWORD Status = inlineUtils::GetStatusCode();
			switch (Status) {
				case Inactive: {
					inlineUtils::KSleep(50);
				} break;

				case Active: {
					inlineUtils::KSleep(1);
				} break;

				case Waiting: {
					inlineUtils::RespondRequest();
				} break;

				case Exit: {
					inlineUtils::SetStatusCode(Inactive);
					g_Fun->ObfDereferenceObject(g_Fun->gProcess);
					g_Fun->DbgPrintEx(0, 0, g_Fun->Str_CloseCommunication, 2);
					return 2;
				} break;

				default: {
					inlineUtils::KSleep(50);
				} break;
			}

		}
	}
	g_Fun->DbgPrintEx(0, 0, g_Fun->Str_CloseCommunication, 0);
	
CleanUp:
	return 0;

	//SharedMemory::Loop();
}

DECLSPEC_NOINLINE void NTAPI StartHook()
{	
	//__debugbreak();
	if (auto Mov_pEDD = Utils::FindPatternImage((CHAR*)Real_gFun->gKernelBase,
		"\x48\x8B\x05\x00\x00\x00\x00\x75\x07\x48\x8B\x05\x00\x00\x00\x00\xE8\x00\x00\x00\x00",
		"xxx????xxxxx????x????")) 
	{
		//__debugbreak();

		//resolve mov rax,[Mov_pEDDs]
		#define RVA(addr, size) (BYTE*)addr + *(INT*)((BYTE*)addr + ((size) - 4)) + size
		Real_gFun->pEDD = RVA(Mov_pEDD, 7);
		DbgPrintEx(0, 0, "EDD;%llx EDDHook;%llx\n", (DWORD64)Real_gFun->pEDD, (DWORD64)Real_gFun->EDDHook);
		// Hook EDDs()
		*(PVOID*)&Real_gFun->EDDOriginal = InterlockedExchangePointer((PVOID*)Real_gFun->pEDD, (PVOID)Real_gFun->EDDHook);
		DbgPrintEx(0, 0, "EDDOriginal:%llx EDD:%llx EDDHook:%llx\n", (DWORD64)Real_gFun->EDDOriginal,(DWORD64)Real_gFun->pEDD, (DWORD64)Real_gFun->EDDHook);

	}
}

DECLSPEC_NOINLINE BOOLEAN initializeGlobals()
{
	Real_gFun = (Global_Function_List*)ExAllocatePool(NonPagedPool, 0x1000);
	if (!Real_gFun) { return FALSE; }
	RtlZeroMemory(Real_gFun, 0x1000);

	auto OSInfo{ Utils::GetOSVersion() };

	//var**************************************
	Real_gFun->ActiveThreadsOffset = 0x5F0;
	if (OSInfo.dwBuildNumber < 19041) {
		Real_gFun->ActiveThreadsOffset = OSInfo.dwBuildNumber == 10240 ? 0x490 : 0x498;
	}

	Real_gFun->Str_OutPutCount = (char*)((DWORD64)Real_gFun + 0x700);
	memcpy((PVOID)Real_gFun->Str_OutPutCount, "%d\n", 4);

	Real_gFun->Str_DoNormalEDD = (char*)((DWORD64)Real_gFun + 0x710);
	memcpy((PVOID)Real_gFun->Str_DoNormalEDD, "The Request Dont met criteria, returning\n", 42);

	Real_gFun->Str_CloseCommunication = (char*)((DWORD64)Real_gFun + 0x750);
	memcpy((PVOID)Real_gFun->Str_CloseCommunication, "Communication Closed Code=%d\n", 30);

	Real_gFun->gKernelBase = Utils::GetModuleInfo("ntoskrnl.exe",NULL);
	//var**************************************


	//func*************************************
#define NameFunction(fun) Real_gFun->fun = ::fun
	NameFunction(DbgPrintEx);
	NameFunction(KeDelayExecutionThread); 
	NameFunction(ExGetPreviousMode);  
	NameFunction(MmCopyVirtualMemory); 
	NameFunction(IoGetCurrentProcess);
	NameFunction(PsLookupProcessByProcessId);
	NameFunction(ObfDereferenceObject);
	NameFunction(MmUserProbeAddress);
	NameFunction(PsGetProcessSectionBaseAddress);
	NameFunction(KeStackAttachProcess);
	NameFunction(KeUnstackDetachProcess);
	NameFunction(PsGetProcessPeb);
	NameFunction(ZwQueryInformationProcess);
	NameFunction(RtlCompareUnicodeString);
	NameFunction(RtlInitAnsiString);
	NameFunction(RtlAnsiStringToUnicodeString);
	NameFunction(RtlFreeUnicodeString);
	NameFunction(ZwAllocateVirtualMemory);	
	NameFunction(ZwFreeVirtualMemory);	
	NameFunction(ZwProtectVirtualMemory);
	NameFunction(ZwQueryVirtualMemory);	
	//func*************************************



	//hook*************************************
	Real_gFun->EDDHook = (EnumerateDebuggingDevices)ExAllocatePool(NonPagedPool, 0x2000);
	if (!Real_gFun->EDDHook) return FALSE;
	RtlZeroMemory(Real_gFun->EDDHook, 0x2000);
	memcpy(Real_gFun->EDDHook, EDDHookProc, 0x2000);

	auto FixedCount = FixRelatives(Real_gFun->EDDHook, 0x2000, Real_gFun);
	DbgPrintEx(0, 0, "FixRelatives OK, Fixed: %d Global Stuff\n", FixedCount);
	//hook*************************************


	return TRUE;
}

extern "C" NTSTATUS DriverEntry(
	PDRIVER_OBJECT  driver_object,
	PUNICODE_STRING registry_path
)
{
	//__debugbreak();

	if (!initializeGlobals()) { 
		return STATUS_UNSUCCESSFUL;
	}

	DbgPrintEx(0,0,"Real_gFun %llx\n", (DWORD64)Real_gFun);


	StartHook();

	//return STATUS_SUCCESS;
	return STATUS_UNSUCCESSFUL;
}
