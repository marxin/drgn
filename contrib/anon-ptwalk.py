#!/usr/bin/env python
# vim:set shiftwidth=4 softtabstop=4 expandtab textwidth=79:
# bsc#1196471

# This script uses the page table walk class to find anonymous pages that
# have "lost" their mappings as their page_mapcount() is different than
# actual instances found in page tables.
# Per-mm rss inconsistencies are also reported.

import datetime
from collections import defaultdict
import os

from math import ceil
from concurrent.futures import ProcessPoolExecutor, wait, FIRST_COMPLETED

import drgn
from drgn import Object
from drgn.helpers.common.format import number_in_binary_units
from drgn.helpers.linux.mm import pfn_to_page, page_to_pfn, PageSwapBacked, compound_head, cmdline, for_each_page, PageLRU
from drgn.helpers.linux.pid import find_task, for_each_task
from drgn.helpers.linux.slab import find_slab_cache, slab_cache_for_each_allocated_object
from drgn.helpers.common.memory import identify_address
from drgn.helpers.linux.percpu import percpu_counter_sum

# A small trick how to propagate global name 'prog' to the ptwalk module
import config
config.program = prog

from ptwalk import PTWalk, PAGE_MAPPING_ANON, PAGE_SIZE

try:
    from alive_progress import alive_bar, alive_it
except ImportError:
    print('Missing alive_progress module: pip install alive-progress')
    exit(1)

CPU_COUNT = os.cpu_count()
CHUNK_SIZE = 10 ** 5

def page_mapcount(page):
    head = compound_head(page)
    return head._mapcount.counter.value_() + 1


def split(items, chunk):
    for i in range(ceil(len(items) / chunk)):
        yield items[i * chunk:(i + 1) * chunk]

class MyWalk(PTWalk):
    def __init__(self):
        super().__init__()
#        self.avidx_to_mmaddr = defaultdict(set)

#    def process_anon_page(self, addr, page):
#        anon_vma = int(page.mapping) - 1
#        self.avidx_to_mmaddr[(anon_vma, page.index.value_())].add((int(self.mm), addr,page.value_()))


ptwalk = MyWalk()

mm_counted = dict()
mm_counted_file = dict()
mm_counted_shm = dict()
mm_counted_swap = dict()
mm_rss_anon = dict()
mm_rss_file = dict()
mm_rss_shm = dict()
mm_rss_swap = dict()
mm_task = dict()

def get_task_memory_info(task):
    """
    Return RSS (Resident Set Size) memory and VMS (Virtual Memory Size)
    for a given task. Return None if the task is a kernel thread.
    """
    if not task.mm:
        return None

    vms = PAGE_SIZE * task.mm.total_vm.value_()

    # Since Linux kernel commit f1a7941243c102a44e ("mm: convert mm's rss
    # stats into percpu_counter") (in v6.2), rss_stat is percpu counter.
    try:
        rss = PAGE_SIZE * sum([percpu_counter_sum(x) for x in task.mm.rss_stat])
    except (AttributeError, TypeError):
        rss = PAGE_SIZE * sum([x.counter for x in task.mm.rss_stat.count]).value_()

    return (vms, rss)

task_count = len(list(for_each_task(prog)))
for i, task in enumerate(for_each_task(prog)):
    mm = task.mm
    mmp = int(mm)
    if mmp == 0:
        continue

    if mmp not in mm_counted.keys():
        # command = ' '.join([x.decode() for x in cmdline(task)])
        # This makes libkdumpfile unhappy and I see an zlib decompression error later on
        # command = '[unknown cmdline]'

        vms, rss = get_task_memory_info(task)
        now = datetime.datetime.utcnow().strftime("%c")
        command = task.comm.string_().decode()
        print(f"{now}: pagewalk of task 0x{int(task.value_()):x} mm=0x{mmp:x} {command} "
              f"[VMS={number_in_binary_units(vms)}, RSS={number_in_binary_units(rss)}]")

        with alive_bar(vms, unit='B', scale='IEC', manual=True, title=f'task {i + 1}/{task_count} walk_mm') as bar:
            ptwalk.walk_mm(mm, vms, bar)
        mm_counted[mmp] = ptwalk.anon_count
        mm_counted_file[mmp] = ptwalk.file_count
        mm_counted_shm[mmp] = ptwalk.shm_count
        mm_counted_swap[mmp] = ptwalk.swap_count
        mm_rss_file[mmp] = mm.rss_stat.count[0].counter.value_()
        mm_rss_anon[mmp] = mm.rss_stat.count[1].counter.value_()
        mm_rss_swap[mmp] = mm.rss_stat.count[2].counter.value_()
        mm_rss_shm[mmp] = mm.rss_stat.count[3].counter.value_()
        mm_task[mmp] = [task.value_()]
    else:
        mm_task[mmp].append(task.value_())        

    mm_rss_file[mmp] += task.rss_stat.count[0].value_()
    mm_rss_anon[mmp] += task.rss_stat.count[1].value_()
    mm_rss_swap[mmp] += task.rss_stat.count[2].value_()
    mm_rss_shm[mmp] += task.rss_stat.count[3].value_()

print()
total_rss_diff = 0

for mmp in alive_it(mm_counted.keys(), title='mm_counted'):
    counted = mm_counted[mmp]
    rss = mm_rss_anon[mmp]
    
    if counted != rss:
        print (f"mm 0x{mmp:x} anon rss does not match: counted={counted} rss={rss} for the following tasks:")
        total_rss_diff += rss - counted
        for task in mm_task[mmp]:
            print (hex(task))

    counted = mm_counted_file[mmp]
    rss = mm_rss_file[mmp]
    
    if counted != rss:
        print (f"mm 0x{mmp:x} file rss does not match: counted={counted} rss={rss} for the following tasks:")
        for task in mm_task[mmp]:
            print (hex(task))

    counted = mm_counted_shm[mmp]
    rss = mm_rss_shm[mmp]
    
    if counted != rss:
        print (f"mm 0x{mmp:x} shmem rss does not match: counted={counted} rss={rss} for the following tasks:")
        for task in mm_task[mmp]:
            print (hex(task))

    counted = mm_counted_swap[mmp]
    rss = mm_rss_swap[mmp]
    
    if counted != rss:
        print (f"mm 0x{mmp:x} swap rss does not match: counted={counted} rss={rss} for the following tasks:")
        for task in mm_task[mmp]:
            print (hex(task))

total_map_diff = 0

def check_mapcount_for_pfns(pfns):
    pfns_mapcount = {}
    for pfn in pfns:
        try:
            pfns_mapcount[pfn] = page_mapcount(pfn_to_page(prog, pfn))
        except Exception as e:
            print(e)
    return pfns_mapcount


print(f'ptwalk.anon_pfns_mapcount contains {len(ptwalk.anon_pfns_mapcount.keys())} keys')

with ProcessPoolExecutor(max_workers=CPU_COUNT // 2) as executor:
    keys = list(ptwalk.anon_pfns_mapcount.keys())
    futures = [executor.submit(check_mapcount_for_pfns, chunk) for chunk in split(keys, CHUNK_SIZE)]
    with alive_bar(len(futures), title='ptwalk.anon_pfns_mapcount') as bar:
        for future in futures:
            future.add_done_callback(lambda _: bar())
        wait(futures)

        for future in futures:
            for pfn, mapcount in future.result().items():
                walk_mapcount = ptwalk.anon_pfns_mapcount[pfn]
                if walk_mapcount != mapcount:
                    total_map_diff += mapcount - walk_mapcount
                    print(f"page 0x{pfn_to_page(prog, pfn).value_():x} mapcount is {mapcount} but found only {walk_mapcount} in page tables")

cache = find_slab_cache(prog, 'mm_struct')
for mmp in alive_it(slab_cache_for_each_allocated_object(cache, 'struct mm_struct'), title='slab cache'):
    if mmp.value_() not in mm_task.keys():
        for i in range(4):
            rss = int(mmp.rss_stat.count[i].counter)
            if rss != 0:
                print(f"mm 0x{mmp.value_():x} from slab not found in any task, has rss_stat[{i}] == {rss}")


def parse_pages(index):
    page0 = next(for_each_page(prog))
    pfns = []

    for i in range(index * CHUNK_SIZE, (index + 1) * CHUNK_SIZE):
        page = page0 + i
        try:
            # This may include offline pages which don’t have a valid struct page. Wrap accesses in a try … except drgn.FaultError:
            # https://drgn.readthedocs.io/en/latest/helpers.html?highlight=for_each_page#drgn.helpers.linux.mm.for_each_page
            if PageLRU(page) and page.mapping.value_() & PAGE_MAPPING_ANON:
                pfns.append(int(page_to_pfn(page)))
        except drgn.FaultError:
            continue
    return pfns


def check_anonymous_pfns(pfns):
    global total_map_diff
    for pfn in pfns:
        if pfn in ptwalk.anon_pfns_mapcount.keys():
            # already handled above
            continue

        page = pfn_to_page(prog, pfn)
        mapcount = page_mapcount(page)
        anon_vma = int(page.mapping) - 1
        anon_vma_desc = identify_address(prog, anon_vma)
        print(f"unmapped page {page.value_():x} mapcount {mapcount} with anon_vma {anon_vma:x} index {page.index.value_():x}: {anon_vma_desc}")

        """
        av_idx = (anon_vma, page.index.value_())
        for (mm, addr, page_addr) in ptwalk.avidx_to_mmaddr[av_idx]:
            print(f"    page 0x{page_addr:x} mapped with same anon_vma and index in mm 0x{mm:x} at addr 0x{addr:x}")
        """
        total_map_diff += mapcount


with ProcessPoolExecutor(max_workers=CPU_COUNT // 2) as executor:
    max_pfn = int(prog['max_pfn'])
    parts = ceil(max_pfn / CHUNK_SIZE)
    futures = [executor.submit(parse_pages, i) for i in range(parts)]
    with alive_bar(parts) as bar:
        for future in futures:
            future.add_done_callback(lambda _: bar())

        wait(futures)
        for future in futures:
            check_anonymous_pfns(future.result())

print(f"total anon rss diff {total_rss_diff} mapcount diff {total_map_diff} m2p fails {ptwalk.m2p_fails}")