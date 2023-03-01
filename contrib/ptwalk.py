#!/usr/bin/env python
# vim:set shiftwidth=4 softtabstop=4 expandtab textwidth=79:

from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, wait, FIRST_COMPLETED

from drgn import Object
from drgn.helpers.linux.mm import pfn_to_page, page_to_pfn, PageSwapBacked
from drgn.helpers.linux.pid import find_task

try:
    from alive_progress import alive_bar, alive_it
except ImportError:
    print('Missing alive_progress module: pip install alive-progress')
    exit(1)

# A way how to get global variable called 'prog'.

import config

prog = config.program if config.program else prog

# XXX: all this is x86_64 only, hardcoded because it's #define and not visible
# in debuginfo

PAGE_SHIFT = prog["PAGE_SHIFT"].value_()
PAGE_MASK = prog["PAGE_MASK"].value_()
PAGE_SIZE = prog["PAGE_SIZE"].value_()
PAGE_OFFSET_BASE = prog['page_offset_base'].value_()
ZERO_PFN = prog["zero_pfn"].value_()

print('=== System info ===')
print('PAGE_MASK', hex(PAGE_MASK))
print('PAGE_OFFSET_BASE', hex(PAGE_OFFSET_BASE))
print()

# Use 2 GiB as a chunk size for the parallel VMA walker
VMA_CHUNK_SIZE = 2 * 1024 ** 3

VM_HUGETLB = 0x00400000

PAGE_MAPPING_ANON = 1

PTRS_PER_PTE  = 512

__PHYSICAL_MASK_SHIFT = 46
__PHYSICAL_MASK = (1 << __PHYSICAL_MASK_SHIFT) - 1

PHYSICAL_PAGE_MASK = PAGE_MASK & __PHYSICAL_MASK
PTE_PFN_MASK = PHYSICAL_PAGE_MASK
PTE_FLAGS_MASK = ~PTE_PFN_MASK

PGDIR_SHIFT   = 39
PGDIR_SIZE    = 1 << PGDIR_SHIFT
PGDIR_MASK    = ~(PGDIR_SIZE - 1)
PTRS_PER_PGD  = 512

PUD_SHIFT     = 30
PUD_SIZE      = 1 << PUD_SHIFT
PUD_MASK      = ~(PUD_SIZE - 1)
PTRS_PER_PUD  = 512

PMD_SHIFT     = 21
PMD_SIZE      = 1 << PMD_SHIFT
PMD_MASK      = ~(PMD_SIZE - 1)
PTRS_PER_PMD  = 512

_PAGE_PRESENT = 1 << 0
_PAGE_RW      = 1 << 1
_PAGE_USER    = 1 << 2
_PAGE_ACCESSED = 1 << 5
_PAGE_DIRTY   = 1 << 6
_PAGE_PSE     = 1 << 7
_PAGE_PROTNONE= 1 << 8
_PAGE_NUMA    = _PAGE_PROTNONE
_PAGE_SPECIAL = 1 << 9
_PAGE_FILE = _PAGE_DIRTY
_PAGE_NX = 1 << 63

_KERNPG_TABLE = (_PAGE_PRESENT | _PAGE_RW | _PAGE_ACCESSED | _PAGE_DIRTY)
ignore_flags = _PAGE_USER|_PAGE_NX

def __va(addr):
    return PAGE_OFFSET_BASE + int(addr)

def m2p(maddr):
    # Do not expect xen here
    return maddr

def mfn2pfn(pfn):
    # Do not expect xen here
    return pfn

def pgd_addr_end(addr, end):
    __boundary = ((addr) + PGDIR_SIZE) & PGDIR_MASK
    if __boundary - 1 < end:
        return __boundary
    else:
        return end

def pud_addr_end(addr, end):
    __boundary = ((addr) + PUD_SIZE) & PUD_MASK
    if __boundary - 1 < end:
        return __boundary
    else:
        return end

def pmd_addr_end(addr, end):
    __boundary = ((addr) + PMD_SIZE) & PMD_MASK
    if __boundary - 1 < end:
        return __boundary
    else:
        return end

def pgd_val(pgdp):
    return int(pgdp.pgd)

def pud_val(pudp):
    return int(pudp.pud)

def pmd_val(pmdp):
    return int(pmdp.pmd)

def pte_val(ptep):
    return int(ptep.pte)

def pgd_flags(pgdp):
    return pgd_val(pgdp) & PTE_FLAGS_MASK

def pud_flags(pudp):
    return pud_val(pudp) & PTE_FLAGS_MASK

def pmd_flags(pmdp):
    return pmd_val(pmdp) & PTE_FLAGS_MASK

def pte_flags(ptep):
    return pte_val(ptep) & PTE_FLAGS_MASK

def pgd_page_vaddr(pgdp):
    pgdval = pgd_val(pgdp)
    return __va(m2p(pgdval & PTE_PFN_MASK))

def pud_page_vaddr(pudp):
    pudval = pud_val(pudp)
    return __va(m2p(pudval & PTE_PFN_MASK))

def pmd_page_vaddr(pmdp):
    pmdval = pmd_val(pmdp)
    return __va(m2p(pmdval & PTE_PFN_MASK))

def pmd_pfn(pmdp):
    return (pmd_val(pmdp) & PTE_PFN_MASK) >> PAGE_SHIFT

def pte_pfn(ptep):
    return (pte_val(ptep) & PTE_PFN_MASK) >> PAGE_SHIFT

def pgd_offset(mm, addr):
    pgd_index = (addr >> PGDIR_SHIFT) & (PTRS_PER_PGD-1)
    pgd = mm.pgd + pgd_index
    return pgd

def pgd_none_or_bad(pgdp):
    pgdval = pgd_val(pgdp)
    if pgdval == 0:
        return True
    if pgd_bad(pgdp):
        print ("pgd %x bad" % pgdp)
        return True

def pud_none_or_bad(pudp):
    pudval = pud_val(pudp)
    if pudval == 0:
        return True
    if pud_bad(pudp):
        print ("pud %x bad" % pudp)
        return True

def pmd_none(pmdp):
    return pmd_val(pmdp) == 0

def pte_none(ptep):
    return pte_val(ptep) == 0

def pgd_bad(pgdp):
    return (pgd_flags(pgdp) & ~ignore_flags) != _KERNPG_TABLE

def pud_bad(pudp):
    return ((pud_flags(pudp) & ~(_KERNPG_TABLE | _PAGE_USER)) != 0);

def pmd_bad(pmdp):
    flags = pmd_flags(pmdp)
    if (flags & (_PAGE_NUMA|_PAGE_PRESENT)) == _PAGE_NUMA:
        return False
    return (flags & ~_PAGE_USER) != _KERNPG_TABLE

def pte_present(ptep):
    return ((pte_flags(ptep) & (_PAGE_PRESENT | _PAGE_PROTNONE | _PAGE_NUMA)) != 0)

def pte_file(ptep):
    return ((pte_flags(ptep) & _PAGE_FILE))

def pmd_trans_huge(pmdp):
    return (pmd_val(pmdp) & _PAGE_PSE) != 0

def pud_offset(pgdp, addr):
    pud_index = (addr >> PUD_SHIFT) & (PTRS_PER_PUD-1)

    pud_addr = pgd_page_vaddr(pgdp)
    pudp = Object(prog, 'pud_t *',pud_addr)
    pudp += pud_index
    return pudp

def pmd_offset(pudp, addr):
    pmd_index = (addr >> PMD_SHIFT) & (PTRS_PER_PMD-1)

    pmd_addr = pud_page_vaddr(pudp)
    pmdp = Object(prog, 'pmd_t *', pmd_addr)
    pmdp += pmd_index
    return pmdp

def pte_offset(pmdp, addr):
    pte_index = (addr >> PAGE_SHIFT) & (PTRS_PER_PTE-1)

    pte_addr = pmd_page_vaddr(pmdp)
    ptep = Object(prog, 'pte_t *', pte_addr)
    ptep += pte_index
    return ptep

SWP_TYPE_BITS = 5
MAX_SWAPFILES_SHIFT = 5
# XXX for now just assume everything optional is enabled
MAX_SWAPFILES = (1 << MAX_SWAPFILES_SHIFT) - 2 - 2 - 1

def ptep_to_swp_type(ptep):
    pteval = pte_val(ptep)
    return pteval >> (64 - SWP_TYPE_BITS)

def non_swap_entry_ptep(ptep):
    return ptep_to_swp_type(ptep) >= MAX_SWAPFILES


class Counter:
    def __init__(self):
        self.anon = 0
        self.file = 0
        self.shm = 0
        self.swap = 0
        self.m2p_fails = 0

    def __add__(self, other):
        # FIXME: should be a better way
        c = Counter()
        c.anon = self.anon + other.anon
        c.file = self.file + other.file
        c.shm = self.shm + other.shm
        c.swap = self.swap + other.swap
        c.m2p_fails = self.m2p_fails + other.m2p_fails
        return c


class PTSubWalk:

    def __init__(self, size, intervals, vma_addr, mm_addr) -> None:
        self.size = size
        self.intervals = intervals
        self.vma_addr = vma_addr
        self.mm_addr = mm_addr
        self.anon_pfns_mapcount = defaultdict(int)
        self.counts = Counter()

    def process_anon_page(self, addr, page):
        pass

    def vm_normal_page(self, addr, ptep):

        pfn = pte_pfn(ptep)

        if pte_flags(ptep) & _PAGE_SPECIAL:
            #print "pte is special"
            return None

        if pfn == ZERO_PFN:
            return None

        pfn = mfn2pfn(pfn)

        if pfn is None:
            pteval = pte_val(ptep)
            self.counts.m2p_fails += 1
            print(f"m2p failed for addr 0x{addr:x} ptep 0x{int(ptep):x} pte_val 0x{pteval:x}")
            return None

        try:
            return pfn_to_page(prog, pfn)
        except Exception:
            pteval = pte_val(ptep)
            print(f"failed to get page for addr 0x{addr:x} ptep 0x{int(ptep):x} pte_val 0x{pteval:x} pfn {pfn}")
            return None

    def walk_pte_range(self, pmdp, addr, end):

        ptep = pte_offset(pmdp, addr)

        while addr != end:

            if pte_none(ptep):
                addr += PAGE_SIZE
                ptep += 1
                continue

            if pte_present(ptep):
                page = self.vm_normal_page(addr, ptep)

                if page:
                    try:
                        if page.mapping.value_() & PAGE_MAPPING_ANON:
                            self.counts.anon += 1
                            self.anon_pfns_mapcount[page_to_pfn(page).value_()] += 1
                            self.process_anon_page(addr, page)
                        elif PageSwapBacked(page):
                            self.counts.shm += 1
                        else:
                            self.counts.file += 1
                    except Exception as e:
                        print(e)
            else:
                if not non_swap_entry_ptep(ptep):
                    self.counts.swap += 1
                else:
                    pteval = pte_val(ptep)
                    # XXX: handle migration entries
                    print(f"non_swap swap entry in vma=0x{self.vma_addr:x} addr=0x{addr:x} pte_val=0x{pteval:x}")

            addr += PAGE_SIZE
            ptep += 1

        return addr

    def walk_pmd_range(self, pudp, addr, end):

        pmdp = pmd_offset(pudp, addr)
        while addr != end:
            next_addr = pmd_addr_end(addr, end)
            if pmd_none(pmdp):
                pmdp += 1
                addr = next_addr
                continue
            if pmd_trans_huge(pmdp):
                pfn = pmd_pfn(pmdp)
                self.counts.anon += PTRS_PER_PTE
                self.anon_pfns_mapcount[pfn] += 1

                pmdp += 1
                addr = next_addr
                continue
            if pmd_bad(pmdp):
                pmdp += 1
                addr = next_addr
                continue

            self.walk_pte_range(pmdp, addr, next_addr)
            pmdp += 1
            addr = next_addr

        return addr

    def walk_pud_range(self, pgdp, addr, end):

        pudp = pud_offset(pgdp, addr)
        while addr != end:
            next_addr = pud_addr_end(addr, end)
            if pud_none_or_bad(pudp):
                pudp += 1
                addr = next_addr
                continue

            self.walk_pmd_range(pudp, addr, next_addr)
            pudp += 1
            addr = next_addr

        return addr

    def walk_vma(self, mm, interval):
        vm_start, vm_end = interval

        pgdp = pgd_offset(mm, vm_start)
        pgdval = pgdp.pgd

        addr = vm_start
        while addr != vm_end:
            next_addr = pgd_addr_end(addr, vm_end)

            if pgd_none_or_bad(pgdp):
                pgdp += 1
                addr = next_addr
                continue

            self.walk_pud_range(pgdp, addr, next_addr)
            pgdp += 1
            addr = next_addr

    def walk(self):
        mm = Object(prog, 'struct mm_struct *', self.mm_addr)
        for interval in self.intervals:
            self.walk_vma(mm, interval)
        return (self.anon_pfns_mapcount, self.counts)

class PTWalk:
    def __init__(self) -> None:
        self.anon_pfns_mapcount = defaultdict(int)
        self.counts = Counter()

    def split(self, intervals):
        while intervals:
            size = 0
            i = 0

            while i < len(intervals):
                start, end = intervals[i]
                i += 1

                size += end - start
                if size > VMA_CHUNK_SIZE:
                    break

            yield (size, intervals[:i])
            intervals = intervals[i:]

    def merge_subwalker(self, anon_pfns_mapcount, counts):
        for k, v in anon_pfns_mapcount.items():
            self.anon_pfns_mapcount[k] += v
        self.counts += counts


    def walk_mm(self, mm, title):
        self.counts = Counter()
        vma = mm.mmap
        intervals = []

        while vma:
            if not vma.vm_flags & VM_HUGETLB:
                intervals.append((int(vma.vm_start), int(vma.vm_end)))
            vma = vma.vm_next

        # Split the intervals and sort by size
        parts = sorted(self.split(intervals), key=lambda x: 0, reverse=True)
        with alive_bar(len(parts), title=title) as bar:
            if len(parts) == 1:
                size, intervals = parts[0]
                ptsubwalk = PTSubWalk(size, intervals, int(vma), int(mm))
                ptsubwalk.walk()
                self.merge_subwalker(ptsubwalk.anon_pfns_mapcount, ptsubwalk.counts)
                bar()
            else:
                with ProcessPoolExecutor() as executor:
                    futures = []

                    for size, intervals in parts:
                        ptsubwalk = PTSubWalk(size, intervals, int(vma), int(mm))
                        futures.append(executor.submit(ptsubwalk.walk))
                    for future in futures:
                        future.add_done_callback(lambda future: self.merge_subwalker(*future.result()))
                        future.add_done_callback(lambda _: bar())
                    wait(futures)


# Demo usage of PTWalk class for PID == 1 (systemd)

if __name__ == "__main__":
    task = find_task(prog, 1)
    ptwalk = PTWalk()
    ptwalk.walk_mm(task.mm)

    print('anon_count file_count shm_count swap_count')
    print(ptwalk.counts.anon, ptwalk.counts.file, ptwalk.counts.shm, ptwalk.counts.swap)
    print(ptwalk.anon_pfns_mapcount)
