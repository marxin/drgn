import drgn
from drgn import NULL, Object, cast, container_of, execscript, offsetof, reinterpret, sizeof
from drgn.helpers.common import *
from drgn.helpers.linux import *
from drgn.helpers.linux.mm import pfn_to_page, page_to_pfn, PageSwapBacked, compound_head, cmdline, for_each_page, PageLRU, PageSlab

from math import ceil

from alive_progress import alive_bar
import concurrent.futures

pages = int(prog['max_pfn'])
print(f'Visiting {pages} pages')

PAGE_MAPPING_ANON = 1
CHUNK = 10 ** 5


def parse_pages(index):
    vmemmap = prog["vmemmap"]
    pfns = set()
    seen, not_compound, slab = 0, 0, 0

    for i in range(index * CHUNK, (index + 1) * CHUNK):
        page = vmemmap + i
        try:
            if PageLRU(page) and page.mapping.value_() & PAGE_MAPPING_ANON:
                pfn = page_to_pfn(page).value_()
                pfns.add(pfn)
                head = compound_head(page)
                head._mapcount.counter.value_() + 1
                seen += 1
                if page == head:
                    not_compound += 1
            elif PageSlab(page):
                slab += 1
        except drgn.FaultError:
            continue
    return (seen, not_compound, slab, pfns)


with concurrent.futures.ProcessPoolExecutor() as executor:
    futures = set()
    part_count = ceil(pages / CHUNK)
    print('part count:', part_count)
    for i in range(part_count):
        futures.add(executor.submit(parse_pages, i))

    pfns = set()
    total_seen, total_not_compound, total_slab = 0, 0, 0

    with alive_bar(part_count * CHUNK, manual=True, unit='page', scale='SI') as bar:
        while futures:
            done, not_done = concurrent.futures.wait(futures, return_when=concurrent.futures.FIRST_COMPLETED)
            for future in done:
                seen, not_compound, slab, pset = future.result()
                total_seen += seen
                total_not_compound += not_compound
                total_slab += slab
                pfns |= pset
            futures -= done
            bar(1 - len(futures) / part_count)

print(f'pfns set size is {len(pfns)}')
print(f'seen pages: {total_seen}, not in compound page: {total_not_compound}, slab: {total_slab}')
