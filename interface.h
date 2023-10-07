
#ifndef _INTERFACE_H_
#define _INTERFACE_H_

#define MAX_SMRAM_REGIONS 0x10

/* 
    SW SMI command value for communicating with backdoor SMM code
*/
#define BACKDOOR_SW_SMI_VAL 0xcc

/*
    Name and GUID of NVRAM variable to store debug messages buffer address
*/
#define BACKDOOR_VAR_NAME L"SmmBackdoorInfo"
#define BACKDOOR_VAR_GUID { 0xcacdf34, 0xee00, 0x4230, \
                          { 0xaf, 0x5d, 0x8b, 0xae, 0x0, 0x72, 0xcb, 0xea } }

/*
    Backdoor CTL commands
*/
#define BACKDOOR_CTL_PING           0x00   // check if backdoor is alive
#define BACKDOOR_CTL_INFO           0x01   // return backdoor information
#define BACKDOOR_CTL_READ_PHYS      0x02   // read physical memory
#define BACKDOOR_CTL_READ_VIRT      0x03   // read virtual memory
#define BACKDOOR_CTL_WRITE_PHYS     0x04   // write physical memory
#define BACKDOOR_CTL_WRITE_VIRT     0x05   // write virtual memory
#define BACKDOOR_CTL_EXECUTE        0x06   // execute code at given address
#define BACKDOOR_CTL_MSR_GET        0x07   // get MSR value
#define BACKDOOR_CTL_MSR_SET        0x08   // set MSR value
#define BACKDOOR_CTL_STATE_GET      0x09   // get saved state register value
#define BACKDOOR_CTL_STATE_SET      0x0a   // set saved state register value
#define BACKDOOR_CTL_GET_PHYS_ADDR  0x0b   // translate virtual address to physical
#define BACKDOOR_CTL_TIMER_ENABLE   0x0c   // enable periodic timer software SMI
#define BACKDOOR_CTL_TIMER_DISABLE  0x0d   // disable periodic timer software SMI
#define BACKDOOR_CTL_FIND_VMCS      0x0e   // find potential VMCS region

/* 
    Magic register values to communicate with the backdoor
    using periodic timer software SMI handler
*/
#define BACKDOOR_CALL_R8_VAL 0xfe4020d4e8fa6c4d
#define BACKDOOR_CALL_R9_VAL 0xd344171e43eafc19

#pragma pack(1)

typedef struct _BACKDOOR_SMRAM_REGION
{
    UINT64 Addr;
    UINT64 Size;

} BACKDOOR_SMRAM_REGION,
*PBACKDOOR_SMRAM_REGION;

/*
    Arguments for backdoor CTL commands
*/
typedef struct _BACKDOOR_CTL
{
    UINT64 Status;

    union
    {
        // for BACKDOOR_CTL_INFO
        struct
        {
            UINT64 Cr0;
            UINT64 Cr3;
            UINT64 Smst;
            BACKDOOR_SMRAM_REGION Smram[MAX_SMRAM_REGIONS];

        } Info;

        /* 
            for BACKDOOR_CTL_READ_PHYS, BACKDOOR_CTL_READ_VIRT,
                BACKDOOR_CTL_WRITE_PHYS, BACKDOOR_CTL_WRITE_VIRT
        */
        struct
        {
            UINT64 Addr;
            UINT64 Size;
            UINT64 Buff;

        } Mem;

        // for BACKDOOR_CTL_EXECUTE
        struct
        {
            UINT64 Addr;

        } Execute;

        // for BACKDOOR_CTL_MSR_GET, BACKDOOR_CTL_MSR_SET
        struct
        {
            UINT64 Register;
            UINT64 Value;

        } Msr;

        // for BACKDOOR_CTL_STATE_GET, BACKDOOR_CTL_STATE_SET
        struct
        {
            UINT64 Register;
            UINT64 Value;

        } SaveState;

        // for BACKDOOR_CTL_GET_PHYS_ADDR
        struct 
        {
            UINT64 AddrVirt;
            UINT64 AddrPhys;
            UINT64 Eptp;
            UINT64 Cr3;

        } PhysAddr;

        // for BACKDOOR_CTL_FIND_VMCS
        struct 
        {
            UINT64 Addr;
            UINT64 Size;
            UINT64 Found;

        } FindVmcs;

    } Args;

} BACKDOOR_CTL,
*PBACKDOOR_CTL;

#pragma pack()

#endif
