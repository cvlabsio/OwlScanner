#include <algorithm>
#include <string>
#include <thread>
#include <iostream>
#include <unordered_map>
#include <vector>

#include <Windows.h>
#include <DbgHelp.h>
#include <winternl.h>

#define TOKENIZE(x) #x
#define CONCAT( X, Y ) X##Y

template< typename modHandleType, typename procNameType >
auto getProcAddressOrThrow(modHandleType modHandle, procNameType procName) {
	auto address = GetProcAddress(modHandle, procName);
	if (address == nullptr) throw std::exception{
		(std::string{"Error importing: "} + procName).c_str()
	};
	return address;
}

#define IMPORTAPI( DLLFILE, FUNCNAME, RETTYPE, ... )                            \
   typedef RETTYPE( WINAPI* CONCAT( t_, FUNCNAME ) )( __VA_ARGS__ );            \
template< typename... Ts >                                                      \
auto FUNCNAME( Ts... ts ) {                                                     \
	const static CONCAT( t_, FUNCNAME ) func =                                  \
	(CONCAT( t_, FUNCNAME )) getProcAddressOrThrow( ( LoadLibraryW( DLLFILE ),  \
	GetModuleHandleW( DLLFILE ) ), #FUNCNAME );                                 \
	return func(  std::forward< Ts >( ts )... );                                \
}; 

IMPORTAPI(L"NTDLL.dll", NtOpenProcess, NTSTATUS, PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, CLIENT_ID*);
NTSTATUS UniqueProcessIdToHandle(HANDLE UniqueProcessId, PHANDLE processHandle)
{
	OBJECT_ATTRIBUTES oa;
	CLIENT_ID cid;
	cid.UniqueThread = nullptr;
	cid.UniqueProcess = UniqueProcessId;
	InitializeObjectAttributes(&oa, nullptr, 0, nullptr, nullptr);

	return NtOpenProcess(processHandle, PROCESS_QUERY_INFORMATION, &oa, &cid);
}


struct AddressInformation
{
#pragma comment(lib, "dbghelp.lib" )
	AddressInformation(HANDLE processHandle, PVOID address) : address{ address }, hasSymbol{ false }, displacement{ 0 }
	{
		if (address != nullptr)
		{
			constexpr int maxSymNameLength = 256;
			ULONG64 buffer[sizeof(SYMBOL_INFO) + maxSymNameLength] = { 0 };
			const auto symbolBuffer = reinterpret_cast<PSYMBOL_INFO>(buffer);

			symbolBuffer->SizeOfStruct = sizeof(SYMBOL_INFO);
			symbolBuffer->MaxNameLen = MAX_SYM_NAME;

			hasSymbol = SymFromAddr(processHandle, reinterpret_cast<DWORD64>(address), &displacement, symbolBuffer);
			if (hasSymbol)
			{
				symbolName = std::string{ symbolBuffer->Name };
			}

		}
	}

	PVOID address;
	bool hasSymbol;

	std::string symbolName;
	DWORD64 displacement;
};

struct MemoryInformation
{
	MemoryInformation(PVOID baseAddress) : baseAddress{ baseAddress }
	{ }

	PVOID baseAddress;
};

struct ThreadInformation
{
	IMPORTAPI(L"NTDLL.dll", NtQueryInformationThread, NTSTATUS, HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG);
	ThreadInformation(HANDLE processHandle, HANDLE threadHandle) : threadId{ GetThreadId(threadHandle) }
	{
		//
		// we expect a valid handle
		// our caller is responsible for closing the thread handle
		//

		threadContext.ContextFlags = CONTEXT_ALL;
		if (GetThreadContext(threadHandle, &threadContext))
		{
			for(int i = 0; i < 4; i++)
			{
				if ((&threadContext.Dr0)[i])
				{
					debugRegisterInformation.emplace_back(AddressInformation{ processHandle, reinterpret_cast<PVOID>((&threadContext.Dr0)[i]) });
				}
			}
		}

		constexpr ULONG ThreadQuerySetWin32StartAddress = 9UL;
		ULONG returnLength;
		PVOID startAddress;
		NTSTATUS status = NtQueryInformationThread(threadHandle, static_cast<THREADINFOCLASS>(ThreadQuerySetWin32StartAddress),
			&startAddress, sizeof(PVOID), &returnLength);
		if (NT_SUCCESS(status))
		{
			startAddressInformation = std::make_shared<AddressInformation>(processHandle, startAddress);
		}
	}

	DWORD threadId;

	std::shared_ptr<AddressInformation> startAddressInformation;
	//
	// Resolve walked stack frame symbols
	//
	PVOID stackFrames[150];
	//
	// Check for debug registers
	//
	std::vector<AddressInformation> debugRegisterInformation;
	//
	// Full thread context - not decorated 
	//
	CONTEXT threadContext;
};

struct SectionInformation
{
	SectionInformation(PVOID ModuleBase, std::string SectionName) : SectionName{ std::move(SectionName) }
	{
		//
		// Parse all the sections
		//
		SectionSZ = SectionVA = 0;
	}

	std::string SectionName;

	PVOID SectionVA;
	PVOID SectionSZ;
};

struct ModuleInformation
{
	ModuleInformation(PVOID baseAddress, std::wstring moduleName, std::wstring fullDiskPath) : baseAddress{ baseAddress }, moduleName{ moduleName }, fullDiskPath{ fullDiskPath }, copyOnWrite{ false }
	{

	}

	//
	// General
	// 
	PVOID baseAddress;
	std::wstring moduleName;
	std::wstring fullDiskPath;

	//
	// Protections
	//
	MemoryInformation memoryInformation{ baseAddress };
	//
	// copyOnWrite 
	//
	bool copyOnWrite;
	//
	// section information
	//
	std::vector< SectionInformation > sectionInformation;
};

struct Modules
{
	IMPORTAPI(L"NTDLL.dll", NtQueryInformationProcess, NTSTATUS, HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
	IMPORTAPI(L"NTDLL.dll", NtClose, NTSTATUS, HANDLE);

	Modules(HANDLE UniqueProcessId)
	{
		HANDLE processHandle;
		NTSTATUS status = UniqueProcessIdToHandle(UniqueProcessId, &processHandle);
		if (NT_SUCCESS(status))
		{
			PROCESS_BASIC_INFORMATION pbi;
			ULONG returnLength;
			status = NtQueryInformationProcess(processHandle, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), &returnLength);

			NtClose(processHandle);
		}
	}

	std::vector< ModuleInformation > moduleInformation;
};

struct Processes
{
	IMPORTAPI(L"NTDLL.dll", NtQuerySystemInformation, NTSTATUS, SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

	Processes()
	{
		ULONG bufferlen = 0;
		PVOID buffer;

		//
		// Required to resolve symbols at a later time.
		//
		SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME | SYMOPT_INCLUDE_32BIT_MODULES);

		NTSTATUS status = NtQuerySystemInformation(SystemProcessInformation, nullptr, bufferlen, &bufferlen);
		for (;;)
		{
			buffer = new BYTE[bufferlen];
			status = NtQuerySystemInformation(SystemProcessInformation, buffer, bufferlen, &bufferlen);
			if (!NT_SUCCESS(status))
			{
				delete[] buffer;
				buffer = nullptr;
			}
			else break;
		}
		if (buffer != nullptr)
		{
			auto iterator = static_cast<SYSTEM_PROCESS_INFORMATION*>(buffer);
			for (;;)
			{
				if (iterator->ImageName.Buffer)
				{
					processIds.emplace_back(std::make_tuple(iterator->UniqueProcessId, std::wstring{ iterator->ImageName.Buffer }));
				}

				if (!iterator->NextEntryOffset) break;
				iterator = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(reinterpret_cast<PUCHAR>(iterator) + iterator->NextEntryOffset);
			}

			delete[] buffer;
		}
	}

	[[nodiscard]]
	auto& getProcesses() const
	{
		return processIds;
	}

	std::vector< std::tuple<HANDLE, std::wstring> > processIds;
};

struct Threads
{
	IMPORTAPI(L"NTDLL.dll", NtClose, NTSTATUS, HANDLE);
	IMPORTAPI(L"NTDLL.dll", NtGetNextThread, NTSTATUS, HANDLE, HANDLE, ACCESS_MASK, ULONG, ULONG, PHANDLE);

	//
	// Takes UniqueProcessId -> Iterates through all the threads <- ThreadInformation -> stored in threadInformation
	//
	Threads(HANDLE UniqueProcessId)
	{
		HANDLE processHandle;
		NTSTATUS status = UniqueProcessIdToHandle(UniqueProcessId, &processHandle);
		if (NT_SUCCESS(status))
		{
			//
			// Initialize symbol resolution per process
			//
			SymInitialize(processHandle, nullptr, TRUE);

			SymSetSearchPath(processHandle, "SRV*http://msdl.microsoft.com/download/symbols");

			HANDLE threadHandle = nullptr;
			HANDLE newThreadHandle = nullptr;
			do
			{
				status = NtGetNextThread(processHandle,
					threadHandle,
					THREAD_ALL_ACCESS,	// THREAD_GET_CONTEXT | THREAD_QUERY_LIMITED_INFORMATION (Need THREAD_ALL_ACCESS for start address)
					0,
					0,
					&newThreadHandle);
				if (NT_SUCCESS(status))
				{
					threadInformation.emplace_back(ThreadInformation{ processHandle, threadHandle });

					NtClose(threadHandle);
					threadHandle = newThreadHandle;
				}
			} while (NT_SUCCESS(status));

			//
			// Cleanup process-related activities
			// 
			SymCleanup(processHandle);

			NtClose(processHandle);
			processHandle = nullptr;
		}
	}

	//
	// Iterate through threads of a process
	//
	std::vector< ThreadInformation > threadInformation;
};

struct ProcessInformation
{
	ProcessInformation(HANDLE processId, std::wstring processName) : processId{ processId }, processName{ processName }
	{
		//
		// Change this to parse PE information : )
		//
		IsWow64Process(processId, &isWow64);

		//
		// Iterates through all the threads of the given processId and get's all information
		//
		threadInformation = Threads{ processId }.threadInformation;

		//
		// Get the processes module information
		//
		moduleInformation = Modules{ processId }.moduleInformation;
	}

	HANDLE processId;
	std::wstring processName;

	BOOL isWow64;


	//
	// Iterables
	//
	std::vector< ModuleInformation > moduleInformation;
	std::vector< ThreadInformation > threadInformation;
	std::vector< MemoryInformation > memoryInformation;
};


int main(int argc, const char* argv[])
try
{
	const Processes processes;
	std::vector< ProcessInformation > processInformation;

	for (const auto& processId : processes.getProcesses())
	{
		processInformation.emplace_back(ProcessInformation{ std::get<0>(processId), std::get<1>(processId) });
	}

	for (const auto& process : processInformation)
	{
		for (const auto& thread : process.threadInformation)
		{
			if (!thread.debugRegisterInformation.empty())
			{
				printf("PID: %llu\t", reinterpret_cast<ULONG_PTR>(process.processId));
				printf("TID: %lu\n", thread.threadId);
				printf("\nPROC_NAME: %S\n", process.processName.c_str());

				for(const auto& dr : thread.debugRegisterInformation)
				{
					printf("DR: 0x%p:\t", dr.address);
					if (dr.hasSymbol)
					{
						printf("%s + 0x%llx\n", dr.symbolName.c_str(), dr.displacement);
					}
					else
					{
						printf("[NO-SYMBOL]\n");
					}
				}
			}
			//if (thread.startAddressInformation)
			//{
			//	if (thread.startAddressInformation->hasSymbol)
			//	{
			//		printf("0x%p:\t%s + 0x%llx\n", thread.startAddressInformation->address, thread.startAddressInformation->symbolName.c_str(), thread.startAddressInformation->displacement);
			//	}
			//	else
			//	{
			//		printf("0x%p: [NO SYMBOL]\n", thread.startAddressInformation->address);
			//	}
			//}
		}
	}

	getchar();
}
catch (std::exception& e) { std::cout << e.what() << std::endl; }
catch (...) { std::cout << "Critical Error" << std::endl; }
