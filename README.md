
# SMM Backdoor Next Gen

This version of System Management Mode backdoor for UEFI based platforms was heavily inspired by [my previous project](http://blog.cr4.sh/2015/07/building-reliable-smm-backdoor-for-uefi.html) (check [its GitHub repository](https://github.com/Cr4sh/SmmBackdoor)) but introducing few key changes in order to make it more up to date:

 * New SMM backdoor can be deployed with pre-boot DMA attack using [PCI Express DIY hacking toolkit](https://github.com/Cr4sh/s6_pcie_microblaze) (see [uefi_backdoor_simple.py](https://github.com/Cr4sh/s6_pcie_microblaze/blob/master/python/uefi_backdoor_simple.py) program usage for more details) and industry-wide EFI SMM Core vulnerability exploitation to perform DXE to SMM execution transition.

 * Client program `smm_backdoor.py` supports Windows and Linux systems and can interact with SMM backdoor using SW SMI (requires high privileges and [chipsec](https://github.com/chipsec/chipsec) installed) or APIC periodic timer method that can work with any privileges level.

 * There's `smm_backdoor_privesc_linux.py` and `smm_backdoor_privesc_win.py` test client programs for SMM backdoor that demonstrating local privileges escalation under Windows and Linux by using its API provided by `smm_backdoor.py` library.

 * SMM backdoor is fully vitalization-aware now, its library and client programs can work as expected inside Windows or Linux virtual machines running on the infected host system.

Project documentation is incomplete at this moment.

Developed by:
Dmytro Oleksiuk (aka Cr4sh)

[cr4sh0@gmail.com](mailto:cr4sh0@gmail.com)
[http://blog.cr4.sh](http://blog.cr4.sh)
