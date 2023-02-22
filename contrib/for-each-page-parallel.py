import drgn
from drgn import NULL, Object, cast, container_of, execscript, offsetof, reinterpret, sizeof
from drgn.helpers.common import *
from drgn.helpers.linux import *
from drgn.helpers.linux.mm import pfn_to_page, page_to_pfn, PageSwapBacked, compound_head, cmdline, for_each_page, PageLRU

from math import ceil

import concurrent.futures

pages = int(prog["max_pfn"])
print(f'Visiting {pages} pages')

PAGE_MAPPING_ANON = 1
CHUNK = 10 ** 6

def parse_pages(index):
    vmemmap = prog["vmemmap"]
    pfns = set()

    for i in range(index * CHUNK, (index + 1) * CHUNK):
        page = vmemmap + i
        try:
            if PageLRU(page) and page.mapping.value_() & PAGE_MAPPING_ANON:
                pfn = page_to_pfn(page).value_()
                pfns.add(pfn)
        except drgn.FaultError:
            continue
    return pfns

with concurrent.futures.ProcessPoolExecutor() as executor:
    futures = []
    part_count = ceil(pages / CHUNK)
    print('part count:', part_count)
    for i in range(part_count):
        futures.append(executor.submit(parse_pages, i))
    concurrent.futures.wait(futures)
    pfns = set()
    for future in futures:
        pfns |= future.result()

print(f'pfns set size is {len(pfns)}')