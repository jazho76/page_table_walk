import gdb


ADDR_MASK = 0x000FFFFFFFFFF000
FLAG_NAMES = [
    (0, "Present"),
    (1, "RW"),
    (2, "User"),
    (3, "PWT"),
    (4, "PCD"),
    (5, "Accessed"),
    (6, "Dirty"),
    (7, "PageSize"),
    (63, "NX"),
]


def read_phys(addr):
    result = gdb.execute(f"monitor xp/1gx {addr:#x}", to_string=True)
    parts = result.strip().split(":")
    if len(parts) < 2:
        raise RuntimeError(f"Unexpected xp output: {result.strip()}")
    return int(parts[1].strip(), 16)


def decode_flags(entry):
    flags = []
    for bit, name in FLAG_NAMES:
        if entry & (1 << bit):
            flags.append(name)
    return " ".join(flags)


def pagewalk(va):
    cr3 = int(gdb.parse_and_eval("$cr3"))
    pgd_base = cr3 & ADDR_MASK

    pgd_idx = (va >> 39) & 0x1FF
    pud_idx = (va >> 30) & 0x1FF
    pmd_idx = (va >> 21) & 0x1FF
    pt_idx = (va >> 12) & 0x1FF
    offset = va & 0xFFF

    print("Decoded Virtual Address:")
    print(f"  PGD={pgd_idx:#05x}")
    print(f"  PUD={pud_idx:#05x}")
    print(f"  PMD={pmd_idx:#05x}")
    print(f"  PT={pt_idx:#05x}")
    print(f"  Offset={offset:#05x}")
    print()

    print(f"CR3: {cr3:#018x}")
    pgd_entry = read_phys(pgd_base + pgd_idx * 8)
    print(f"PGD[{pgd_idx:#05x}]:  {pgd_entry:#018x}  [{decode_flags(pgd_entry)}]")
    if not (pgd_entry & 1):
        print("  -> Not present!")
        return None
    pud_base = pgd_entry & ADDR_MASK

    pud_entry = read_phys(pud_base + pud_idx * 8)
    print(f"PUD[{pud_idx:#05x}]:  {pud_entry:#018x}  [{decode_flags(pud_entry)}]")
    if not (pud_entry & 1):
        print("  -> Not present!")
        return None
    if pud_entry & (1 << 7):
        phys = (pud_entry & 0x000FFFFFC0000000) | (va & 0x3FFFFFFF)
        print(f"  -> 1 GB huge page")
        print(f"\nPhysical address: {phys:#018x}")
        return phys
    pmd_base = pud_entry & ADDR_MASK

    pmd_entry = read_phys(pmd_base + pmd_idx * 8)
    print(f"PMD[{pmd_idx:#05x}]:  {pmd_entry:#018x}  [{decode_flags(pmd_entry)}]")
    if not (pmd_entry & 1):
        print("  -> Not present!")
        return None
    if pmd_entry & (1 << 7):
        phys = (pmd_entry & 0x000FFFFFFFE00000) | (va & 0x1FFFFF)
        print(f"  -> 2 MB huge page")
        print(f"\nPhysical address: {phys:#018x}")
        return phys
    pt_base = pmd_entry & ADDR_MASK

    pt_entry = read_phys(pt_base + pt_idx * 8)
    print(f"PT[{pt_idx:#05x}]:   {pt_entry:#018x}  [{decode_flags(pt_entry)}]")
    if not (pt_entry & 1):
        print("  -> Not present!")
        return None

    frame = pt_entry & ADDR_MASK
    phys = frame | offset

    print(f"\nPhysical address: {phys:#018x}")
    return phys


class PageWalkCommand(gdb.Command):
    def __init__(self):
        super().__init__("pagewalk", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        args = gdb.string_to_argv(arg)
        if len(args) != 1:
            print("Usage: pagewalk <virtual-address>")
            return
        try:
            va = int(args[0], 0)
        except ValueError:
            print(f"Invalid address: {args[0]}")
            return
        pagewalk(va)


PageWalkCommand()
print("Page walk command loaded. Usage: pagewalk <virtual-address>")
