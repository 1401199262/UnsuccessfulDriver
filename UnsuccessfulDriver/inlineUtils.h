#pragma once

//Used Only In Mapped Space!!!
namespace inlineUtils
{
	FORCEINLINE VOID KSleep(ULONG ms)
	{
		LARGE_INTEGER timeout;
		timeout.QuadPart = -10 * 1000;
		timeout.QuadPart *= ms;
		g_Fun->KeDelayExecutionThread(KernelMode, FALSE, &timeout);
	}

	FORCEINLINE BOOLEAN ProbeUserAddress(PVOID Address, SIZE_T Size, DWORD Alignment) {
		if (Size == 0) {
			return TRUE;
		}

		DWORD64 Current = (DWORD64)Address;
		if (((DWORD64)Address & (Alignment - 1)) != 0) {
			return FALSE;
		}

		DWORD64 Last{ Current + Size - 1 };

		if ((Last < Current) || (Last >= g_Fun->MmUserProbeAddress)) {
			return FALSE;
		}

		return TRUE;
	}

	FORCEINLINE BOOLEAN MMCopy(PVOID Destination, PVOID Source, SIZE_T Size) {
		SIZE_T BytesRead{ 0 };
		return NT_SUCCESS(g_Fun->MmCopyVirtualMemory(
			g_Fun->IoGetCurrentProcess(),
			Source,
			g_Fun->IoGetCurrentProcess(),
			Destination,
			Size,
			KernelMode,
			&BytesRead)) && BytesRead == Size;
	}

	FORCEINLINE BOOLEAN ReadSharedMemory(PVOID Address, PVOID Buffer, SIZE_T Size) {
		SIZE_T Bytes{ 0 };

		if (NT_SUCCESS(g_Fun->MmCopyVirtualMemory(g_Fun->gProcess, Address, g_Fun->IoGetCurrentProcess(), Buffer, Size, KernelMode, &Bytes))) {
			return TRUE;
		} return FALSE;
	}

	template <typename T>
	FORCEINLINE BOOLEAN WriteSharedMemory(PVOID Address, T Buffer, SIZE_T Size = sizeof(T)) {
		SIZE_T Bytes{ 0 };

		if (NT_SUCCESS(g_Fun->MmCopyVirtualMemory(g_Fun->IoGetCurrentProcess(), (PVOID)&Buffer, g_Fun->gProcess, Address, Size, KernelMode, &Bytes))) {
			return TRUE;
		} return FALSE;
	}

	FORCEINLINE BYTE GetStatusCode() {
		BYTE CurStatus{ 0 };
		ReadSharedMemory(g_Fun->gCommunicationData.pStatus, &CurStatus, sizeof(SHORT));
		return CurStatus;
	}

	FORCEINLINE BOOLEAN SetStatusCode(StatusCode DesiredStatus) {
		return WriteSharedMemory<SHORT>(g_Fun->gCommunicationData.pStatus, DesiredStatus);
	}

	FORCEINLINE DWORD GetRequestCode() {
		DWORD CurCode{ 0 };
		ReadSharedMemory(g_Fun->gCommunicationData.pCode, &CurCode, sizeof(DWORD));
		return CurCode;
	}

	FORCEINLINE BOOLEAN SetRequestCode() {
		return WriteSharedMemory<DWORD>(g_Fun->gCommunicationData.pCode, Complete);
	}

	FORCEINLINE OperationData GetOperationData() {
		OperationData CurBuffer;
		for (int i = 0; i < sizeof(OperationData); i++) { ((BYTE*)&CurBuffer)[i] = 0; }

		ReadSharedMemory(g_Fun->gCommunicationData.SharedMemory, &CurBuffer, sizeof(OperationData));
		return CurBuffer;
	}

	FORCEINLINE BOOLEAN SetOperationData(OperationData Buffer) {
		return WriteSharedMemory<OperationData>(g_Fun->gCommunicationData.SharedMemory, Buffer);
	}

	namespace Process
	{
		FORCEINLINE PEPROCESS GetProcess(DWORD ProcessId) {
			PEPROCESS eProcess{ nullptr };
			g_Fun->PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(ProcessId), &eProcess);
			return eProcess;
		}

		FORCEINLINE NTSTATUS GetBaseAddress(OperationData* Data) {
			PEPROCESS eProcess{ GetProcess(Data->Process.Id) };

			if (eProcess == nullptr) {
				return STATUS_UNSUCCESSFUL;
			}

			Data->Process.BaseAddress = g_Fun->PsGetProcessSectionBaseAddress(eProcess);

			g_Fun->ObfDereferenceObject(eProcess);
			return Data->Process.BaseAddress ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
		}

		FORCEINLINE NTSTATUS GetMainModuleSize(OperationData* Data) {
			KAPC_STATE Apc{ 0 };
			DWORD Size{ NULL };
			PEPROCESS eProcess{ GetProcess(Data->Process.Id) };

			if (eProcess == nullptr) {
				return STATUS_UNSUCCESSFUL;
			}

			g_Fun->KeStackAttachProcess(eProcess, &Apc);

			if (LIST_ENTRY * ModuleEntry{ g_Fun->PsGetProcessPeb(eProcess)->Ldr->InLoadOrderModuleList.Flink }) {
				Data->Process.Size = CONTAINING_RECORD(ModuleEntry,
					LDR_DATA_TABLE_ENTRY,
					InLoadOrderLinks)->SizeOfImage;
			}

			g_Fun->KeUnstackDetachProcess(&Apc);
			g_Fun->ObfDereferenceObject(eProcess);

			return Data->Process.Size ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
		}

		FORCEINLINE NTSTATUS GetPeb(OperationData* Data) {
			PEPROCESS eProcess{ GetProcess(Data->Process.Id) };

			if (eProcess == nullptr) {
				return STATUS_UNSUCCESSFUL;
			}

			Data->Process.Peb = g_Fun->PsGetProcessPeb(eProcess);

			g_Fun->ObfDereferenceObject(eProcess);
			return Data->Process.Peb ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
		}

		FORCEINLINE NTSTATUS QueryInformation(OperationData* Data) {
			KAPC_STATE Apc{ 0 };
			PEPROCESS eProcess{ GetProcess(Data->Process.Id) };

			if (eProcess == nullptr) {
				return STATUS_UNSUCCESSFUL;
			}

			g_Fun->KeStackAttachProcess(eProcess, &Apc);

			NTSTATUS Status{ g_Fun->ZwQueryInformationProcess(ZwCurrentProcess(),
								   ProcessBasicInformation,
								   &Data->Process.PBI,
								   sizeof(Data->Process.PBI),
								   nullptr) };

			g_Fun->KeUnstackDetachProcess(&Apc);
			g_Fun->ObfDereferenceObject(eProcess);
			return Status;
		}

		FORCEINLINE NTSTATUS GetModuleInfo(OperationData* Data) {
			KAPC_STATE Apc{ 0 };
			PVOID Base{ nullptr };
			DWORD Size{ NULL };
			UNICODE_STRING usModule{ 0 };

			if (Data->Process.Name) {
				ANSI_STRING asModule{ 0 };

				g_Fun->RtlInitAnsiString(&asModule, Data->Process.Name);
				if (!NT_SUCCESS(g_Fun->RtlAnsiStringToUnicodeString(&usModule, &asModule, TRUE))) {
					return STATUS_UNSUCCESSFUL;
				}
			}

			PEPROCESS eProcess{ GetProcess(Data->Process.Id) };

			if (eProcess == nullptr) {
				return STATUS_UNSUCCESSFUL;
			}

			g_Fun->KeStackAttachProcess(eProcess, &Apc);

			LIST_ENTRY* List = &(g_Fun->PsGetProcessPeb(eProcess)->Ldr->InLoadOrderModuleList);

			for (LIST_ENTRY* Entry = List->Flink; Entry != List;) {
				auto Module{ CONTAINING_RECORD(Entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks) };

				if (Module) {
					++Data->Module.Index;

					if (Data->Process.Name && !g_Fun->RtlCompareUnicodeString(&Module->BaseDllName, &usModule, TRUE)) {
						Data->Module.BaseAddress = Module->DllBase;
						Data->Module.SizeOfImage = Module->SizeOfImage;
					}
				}

				Entry = Module->InLoadOrderLinks.Flink;
			}

			g_Fun->KeUnstackDetachProcess(&Apc);
			g_Fun->RtlFreeUnicodeString(&usModule);
			g_Fun->ObfDereferenceObject(eProcess);
			return Data->Module.SizeOfImage ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
		}

		FORCEINLINE NTSTATUS GetModuleInfoByIndex(OperationData* Data) {
			KAPC_STATE Apc{ 0 };
			int Count{ 0 };
			PEPROCESS eProcess{ GetProcess(Data->Process.Id) };

			if (eProcess == nullptr) {
				return STATUS_UNSUCCESSFUL;
			}

			g_Fun->KeStackAttachProcess(eProcess, &Apc);

			LIST_ENTRY* List = &(g_Fun->PsGetProcessPeb(eProcess)->Ldr->InLoadOrderModuleList);

			for (LIST_ENTRY* Entry = List->Flink; Entry != List;) {
				auto Module{ CONTAINING_RECORD(Entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks) };

				if (Module && Count == Data->Module.Index) {
					Data->Module.BaseAddress = Module->DllBase;
					Data->Module.SizeOfImage = Module->SizeOfImage;
					break;
				}

				Count += 1;
				Entry = Module->InLoadOrderLinks.Flink;
			}

			g_Fun->KeUnstackDetachProcess(&Apc);
			g_Fun->ObfDereferenceObject(eProcess);
			return STATUS_SUCCESS;
		}
	};
	
	namespace Memory
	{
		FORCEINLINE NTSTATUS CopyVirtualMemory(OperationData* Data) {
			NTSTATUS Status{ STATUS_SUCCESS };
			PEPROCESS eProcess{ Process::GetProcess(Data->Process.Id) };

			if (eProcess == nullptr) {
				return STATUS_UNSUCCESSFUL;
			}

			if (Data->Memory.Copy.ReadOperation) {
				Status = g_Fun->MmCopyVirtualMemory(eProcess,
					Data->Memory.Copy.Address,
					g_Fun->IoGetCurrentProcess(),
					Data->Memory.Copy.Buffer,
					Data->Memory.Size,
					UserMode,
					&Data->Memory.ReturnLength);
			}
			else {
				Status = g_Fun->MmCopyVirtualMemory(g_Fun->IoGetCurrentProcess(),
					Data->Memory.Copy.Buffer,
					eProcess,
					Data->Memory.Copy.Address,
					Data->Memory.Size,
					UserMode,
					&Data->Memory.ReturnLength);
			}

			g_Fun->ObfDereferenceObject(eProcess);
			return Status;
		}

		FORCEINLINE NTSTATUS AllocateVirtualMemory(OperationData* Data) {
			KAPC_STATE Apc{ NULL };
			PEPROCESS eProcess{ Process::GetProcess(Data->Process.Id) };

			if (eProcess == nullptr) {
				return STATUS_UNSUCCESSFUL;
			}

			g_Fun->KeStackAttachProcess(eProcess, &Apc);

			NTSTATUS Status{ g_Fun->ZwAllocateVirtualMemory(ZwCurrentProcess(),
								 &Data->Memory.Base,
								 NULL,
								 &Data->Memory.Size,
								 Data->Memory.AllocType,
								 Data->Memory.Protect) };

			g_Fun->KeUnstackDetachProcess(&Apc);
			g_Fun->ObfDereferenceObject(eProcess);
			return Status;
		}

		FORCEINLINE NTSTATUS FreeVirtualMemory(OperationData* Data) {
			KAPC_STATE Apc{ NULL };
			PEPROCESS eProcess{ Process::GetProcess(Data->Process.Id) };

			if (eProcess == nullptr) {
				return STATUS_UNSUCCESSFUL;
			}

			g_Fun->KeStackAttachProcess(eProcess, &Apc);

			NTSTATUS Status{ g_Fun->ZwFreeVirtualMemory(ZwCurrentProcess(),
								 &Data->Memory.Base,
								 &Data->Memory.Size,
								 Data->Memory.FreeType) };

			g_Fun->KeUnstackDetachProcess(&Apc);
			g_Fun->ObfDereferenceObject(eProcess);
			return Status;
		}

		FORCEINLINE NTSTATUS ProtectVirtualMemory(OperationData* Data) {
			KAPC_STATE Apc{ NULL };
			PEPROCESS eProcess{ Process::GetProcess(Data->Process.Id) };

			if (eProcess == nullptr) {
				return STATUS_UNSUCCESSFUL;
			}

			g_Fun->KeStackAttachProcess(eProcess, &Apc);

			NTSTATUS Status{ g_Fun->ZwProtectVirtualMemory(ZwCurrentProcess(),
								&Data->Memory.Base,
								&Data->Memory.Size,
								Data->Memory.Protect,
								&Data->Memory.OldProtect) };

			g_Fun->KeUnstackDetachProcess(&Apc);
			g_Fun->ObfDereferenceObject(eProcess);
			return Status;
		}

		FORCEINLINE NTSTATUS QueryVirtualMemory(OperationData* Data) {
			NTSTATUS Status{ STATUS_SUCCESS };
			KAPC_STATE Apc{ 0 };
			PEPROCESS eProcess{ Process::GetProcess(Data->Process.Id) };

			if (eProcess == nullptr) {
				return STATUS_UNSUCCESSFUL;
			}

			g_Fun->KeStackAttachProcess(eProcess, &Apc);

			Status = g_Fun->ZwQueryVirtualMemory(ZwCurrentProcess(),
				Data->Memory.Base,
				MemoryBasicInformation,
				&Data->Memory.MBI,
				sizeof(Data->Memory.MBI),
				&Data->Memory.ReturnLength);

			g_Fun->KeUnstackDetachProcess(&Apc);
			g_Fun->ObfDereferenceObject(eProcess);
			return Status;
		}
	};

	FORCEINLINE VOID RespondRequest() {
		DWORD Code = GetRequestCode();
		OperationData Params = GetOperationData();

		switch (Code) {
			case BaseRequest: {
				Process::GetBaseAddress(&Params);
				SetOperationData(Params);
				SetRequestCode();
				SetStatusCode(Active);
			} break;

			case SizeRequest: {
				Process::GetMainModuleSize(&Params);
				SetOperationData(Params);
				SetRequestCode();
				SetStatusCode(Active);
			} break;

			case PebRequest: {
				Process::GetPeb(&Params);
				SetOperationData(Params);
				SetRequestCode();
				SetStatusCode(Active);
			} break;

			case QIPRequest: {
				Process::QueryInformation(&Params);
				SetOperationData(Params);
				SetRequestCode();
				SetStatusCode(Active);
			} break;

			case CopyRequest: {
				Memory::CopyVirtualMemory(&Params);
				SetOperationData(Params);
				SetRequestCode();
				SetStatusCode(Active);
			} break;

			case AVMRequest: {
				Memory::AllocateVirtualMemory(&Params);
				SetOperationData(Params);
				SetRequestCode();
				SetStatusCode(Active);
			} break;

			case FVMRequest: {
				Memory::FreeVirtualMemory(&Params);
				SetOperationData(Params);
				SetRequestCode();
				SetStatusCode(Active);
			} break;

			case PVMRequest: {
				Memory::ProtectVirtualMemory(&Params);
				SetOperationData(Params);
				SetRequestCode();
				SetStatusCode(Active);
			} break;

			case QVMRequest: {
				Memory::QueryVirtualMemory(&Params);
				SetOperationData(Params);
				SetRequestCode();
				SetStatusCode(Active);
			} break;

			case ModuleRequest: {
				Process::GetModuleInfo(&Params);
				SetOperationData(Params);
				SetRequestCode();
				SetStatusCode(Active);
			} break;

			case IndexRequest: {
				Process::GetModuleInfoByIndex(&Params);
				SetOperationData(Params);
				SetRequestCode();
				SetStatusCode(Active);
			} break;

			default: {
			} break;
		}
	}
	
}