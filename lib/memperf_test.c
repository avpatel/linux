// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bitops.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/timekeeping.h>

static unsigned long memorder  = 12;
module_param(memorder, ulong, 0600);
MODULE_PARM_DESC(memorder, "Log2 of number of pages");

static unsigned long linesz = sizeof(long);
module_param(linesz, ulong, 0600);
MODULE_PARM_DESC(linesz, "Size of cache line");

#define MEM_ORDER	memorder
#define MEM_PAGES	BIT(MEM_ORDER)
#define MEM_SIZE	(PAGE_SIZE * MEM_PAGES)

static __init void memset_perf_test(void)
{
	int i;
	void *dst;
	ktime_t t0, t1;
	struct page *dpage;
	unsigned long long mbps;

	printk("memperf: memset test linesz=%lu memorder=%lu memsize=%luMB\n\n",
		linesz, MEM_ORDER, MEM_SIZE / 1048576UL);

	dpage = alloc_contig_pages(MEM_PAGES, GFP_KERNEL, NUMA_NO_NODE, 0);
	dst = page_to_virt(dpage);

	for (i = 0; i < linesz; i++) {
		t0 = ktime_get();
		memset(dst + i, 0 + i, MEM_SIZE - i);
		t1 = ktime_get();
		mbps = MEM_SIZE * (1000000000ULL / 1048576ULL) * 8ULL;
		mbps = mbps / (t1 - t0);
		printk("memperf: memset(dst+%d): %llu Mb/s\n", i, mbps);
	}

	free_contig_range(page_to_pfn(dpage), MEM_PAGES);

	printk("\n");
}

static __init void memcpy_memmove_perf_test(bool cpy)
{
	int i, j;
	ktime_t t0, t1;
	void *src, *dst;
	unsigned long long mbps;
	struct page *spage, *dpage;

	printk("memperf: %s test linesz=%lu memorder=%lu memsize=%luMB,\n\n",
		(cpy) ? "memcpy" : "memmove", linesz,
		MEM_ORDER, MEM_SIZE / 1048576UL);

	spage = alloc_contig_pages(MEM_PAGES, GFP_KERNEL, NUMA_NO_NODE, 0);
	src = page_to_virt(spage);
	dpage = alloc_contig_pages(MEM_PAGES, GFP_KERNEL, NUMA_NO_NODE, 0);
	dst = page_to_virt(dpage);

	for (i = 0; i < linesz; i++) {
		for (j = 0; j < linesz; j++) {
			t0 = ktime_get();
			if (cpy)
				memcpy(dst + i, src + j, MEM_SIZE - max(i, j));
			else
				memmove(dst + i, src + j, MEM_SIZE - max(i, j));
			t1 = ktime_get();
			mbps = MEM_SIZE * (1000000000ULL / 1048576ULL) * 8ULL;
			mbps = mbps / (t1 - t0);
			printk("memperf: %s(dst+%d, src+%d), distance %lu: %llu Mb/s\n",
				(cpy) ? "memcpy" : "memmove", i, j,
				(j - i) % sizeof(long), mbps);
		}
		printk("\n");
	}

	free_contig_range(page_to_pfn(dpage), MEM_PAGES);
	free_contig_range(page_to_pfn(spage), MEM_PAGES);
}

static __init int memperf_test_init(void)
{
	/* Do memset() performance test */
	memset_perf_test();

	/* Do memcpy() performance test */
	memcpy_memmove_perf_test(true);

	/* Do memmove() performance test */
	memcpy_memmove_perf_test(false);

	return 0;
}

static __exit void memperf_test_exit(void)
{
}

module_init(memperf_test_init);
module_exit(memperf_test_exit);
MODULE_LICENSE("GPL v2");
