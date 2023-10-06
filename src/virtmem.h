
#ifndef _VIRTMEM_H_
#define _VIRTMEM_H_

// PS flag of PDPTE and PDE
#define PDPTE_PDE_PS 0x80

#define PFN_TO_PAGE(_val_) ((_val_) << PAGE_SHIFT)
#define PAGE_TO_PFN(_val_) ((_val_) >> PAGE_SHIFT)

// get MPL4 address from CR3 register value
#define PML4_ADDRESS(_val_) ((_val_) & 0xfffffffffffff000)

// get address translation indexes from virtual address
#define PML4_INDEX(_addr_) (((_addr_) >> 39) & 0x1ff)
#define PDPT_INDEX(_addr_) (((_addr_) >> 30) & 0x1ff)
#define PDE_INDEX(_addr_) (((_addr_) >> 21) & 0x1ff)
#define PTE_INDEX(_addr_) (((_addr_) >> 12) & 0x1ff)

#define PAGE_OFFSET_4K(_addr_) ((_addr_) & 0xfff)
#define PAGE_OFFSET_2M(_addr_) ((_addr_) & 0x1fffff)
#define PAGE_OFFSET_1G(_addr_) ((_addr_) & 0x3fffffff)


// EPT present bit
#define EPT_PRESENT(_val_) (((_val_) & 7) != 0)

// EPT permission flags
#define EPT_R(_val_) (((_val_) & 1) == 1)
#define EPT_W(_val_) (((_val_) & 2) == 2)
#define EPT_X(_val_) (((_val_) & 4) == 4)


typedef struct _CONTROL_REGS
{
    UINT64 Cr0, Cr3, Cr4;

} CONTROL_REGS,
*PCONTROL_REGS;


BOOLEAN Check_IA_32e(void);
BOOLEAN VirtualAddrValid(UINT64 Addr, UINT64 Cr3);
EFI_STATUS PhysicalToPhysical(UINT64 Addr, UINT64 *Ret, UINT64 Eptp, UINT64 SmmCr3);
EFI_STATUS VirtualToPhysical(UINT64 Addr, UINT64 *Ret, UINT64 Cr3, UINT64 Eptp, UINT64 SmmCr3);
BOOLEAN VirtualAddrRemap(UINT64 Addr, UINT64 NewAddr, UINT64 Cr3, BOOLEAN *pbLargePage);

#endif
