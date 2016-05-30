/*
Copyright (c) 2015, HUI. All rights reserved.
*Redistribution and use in source and binary forms, with or without
*modification, are permitted provided that the following conditions are met:
*
*1. Redistributions of source code must retain the above copyright notice,
*this list of conditions and the following disclaimer.
*
*2. Redistributions in binary form must reproduce the above copyright notice,
*this list of conditions and the following disclaimer in the documentation
*and/or other materials provided with the distribution.
*
*3. Neither the name of the copyright holder nor the names of its contributors
*may be used to endorse or promote products derived from this software without
*specific prior written permission.
*
*THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 'AS IS'
*AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
*IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
*ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
*LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
*CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
*SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
*INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
*CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
*ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
*POSSIBILITY OF SUCH DAMAGE.
*/
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/jiffies.h>

#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/poll.h>
#include <linux/rwsem.h>
#include <linux/stddef.h>
#include <linux/device.h>

#include <linux/hrtimer.h>
#include <linux/tick.h>
#include <linux/times.h>
#include <linux/vmalloc.h>

#include <linux/delay.h>
#include <linux/export.h>
#include <linux/kthread.h>
#include <linux/rbtree.h>
#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/cpumask.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/stacktrace.h>
#include <linux/cache.h>
#include <linux/percpu.h>
#include <linux/hardirq.h>
#include <linux/mmzone.h>
#include <linux/slab.h>
#include <linux/thread_info.h>
#include <linux/err.h>
#include <linux/string.h>
#include <linux/nodemask.h>
#include <linux/mm.h>
#include <linux/workqueue.h>

#include <asm/sections.h>
#include <asm/processor.h>
#include <linux/atomic.h>

//#include <linux/kasan.h>
#include <linux/kmemcheck.h>
#include <linux/crc32.h>

#include <asm/sections.h>

#include <linux/kmemcheck.h>
#include <linux/memory_hotplug.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("hui");
MODULE_DESCRIPTION("QKRP module");

static char *funcs = "test";
module_param(funcs,charp,0644);

#define QKRP_MAJOR	3333
#define MAX_NUM 20
static int major = QKRP_MAJOR;
static struct class *qeexo_class;
extern unsigned long volatile jiffies;
static uint8_t index = 0;
int this_cpu;

/*attrs*/
uint32_t qattrs;
uint32_t memleaks;

/*Below parameters is about memleak*/
#define MAX_TRACE		16	/* stack trace length */
#define MAX_SCAN_SIZE		4096	/* maximum size of a scanned block */
#define MIN_COUNT			1

/* flag representing the memory block allocation status */
#define OBJECT_ALLOCATED	(1 << 0)
/* flag set after the first reporting of an unreference object */
#define OBJECT_REPORTED		(1 << 1)
/* flag set to not scan the object */
#define OBJECT_NO_SCAN		(1 << 2)

/* GFP bitmask for qkmp internal allocations */
#define gfp_qkmp_mask(gfp)	(((gfp) & (GFP_KERNEL | GFP_ATOMIC )) | \
				 __GFP_NORETRY | __GFP_NOMEMALLOC | \
				 __GFP_NOWARN)

#define qkmp_stop(x...)	do {	\
	qkmp_disable();		\
} while (0)

/* set if tracing memory operations is enabled */
static int qkmp_enabled=0;
/* allocation caches for qkmp internal data */
static struct kmem_cache *object_cache;
uint32_t malloc_size = 0;
static uint32_t sync_start = 0;
static uint32_t sync_end= 0;
static unsigned long start_addr= 0;
static unsigned long stack_start_addr= 0;
static unsigned long static_start_addr= 0;
static unsigned long end_addr= 0;
static unsigned long stack_end_addr= 0;
static unsigned long static_end_addr= 0;
static unsigned long jiffies_last_scan;

/* minimum and maximum address that may be valid pointers */
static unsigned long min_addr = ULONG_MAX;
static unsigned long max_addr;
/* the list of all allocated objects */
static LIST_HEAD(object_list);
/* the list of gray-colored objects (see color_gray comment below) */
static LIST_HEAD(gray_list);
/* search tree for object boundaries */
static struct rb_root object_tree_root = RB_ROOT;
/* rw_lock protecting the access to object_list and object_tree_root */
static DEFINE_RWLOCK(qkmp_lock);

#define BYTES_PER_POINTER	sizeof(void *)

static struct qkrp_dev_s{
	struct kprobe qkrp;
	int id;
	unsigned long cnt;
	unsigned long avr_duration;
	unsigned long total_duration;
	unsigned long cur_duration;
	unsigned long long pre_t;
	unsigned long long post_t;
	unsigned long pre_nsec;
	unsigned long post_nsec;
	char name[10];
} qkrp_dev[MAX_NUM];

struct qkmp_object{
	spinlock_t lock;
	unsigned long flags;		/* object status flags */
	struct list_head object_list;
	struct list_head gray_list;
	struct rb_node rb_node;
	struct rcu_head rcu;		/* object_list lockless traversal */
	/* object usage count; object freed when use_count == 0 */
	atomic_t use_count;
	unsigned long pointer;
	size_t size;
	/* minimum number of a pointers found before it is considered leak */
	int min_count;
	/* the total number of pointers found pointing to this object */
	int count;
	/* checksum for detecting modified objects */
	u32 checksum;
	/* memory ranges to be scanned inside an object (empty for all) */
	struct hlist_head area_list;
	unsigned long trace[MAX_TRACE];
	unsigned int trace_len;
	unsigned long jiffies;		/* creation timestamp */
	pid_t pid;			/* pid of the current task */
	char comm[TASK_COMM_LEN];	/* executable name */
};

#define QKMP_GREY	0
#define QKMP_BLACK	-1

/*
 * Object colors, encoded with count and min_count:
 * - white - orphan object, not enough references to it (count < min_count)
 * - gray  - not orphan, not marked as false positive (min_count == 0) or
 *		sufficient references to it (count >= min_count)
 * - black - ignore, it doesn't contain references (e.g. text section)
 *		(min_count == -1). No function defined for this color.
 * Newly created objects don't have any color assigned (object->count == -1)
 * before the next memory scan when they become white.
 */
static bool color_white(const struct qkmp_object *object)
{
	return object->count != QKMP_BLACK &&
		object->count < object->min_count;
}

static bool color_gray(const struct qkmp_object *object)
{
	return object->min_count != QKMP_BLACK &&
		object->count >= object->min_count;
}

/*
 * Objects are considered unreferenced only if their color is white, they have
 * not be deleted and have a minimum age to avoid false positives caused by
 * pointers temporarily stored in CPU registers.
 */
static bool unreferenced_object(struct qkmp_object *object)
{
	return (color_white(object) && object->flags & OBJECT_ALLOCATED);
}

/*
 * Save stack trace to the given array of MAX_TRACE size.
 */
static int __save_stack_trace(unsigned long *trace)
{
	struct stack_trace stack_trace;

	stack_trace.max_entries = MAX_TRACE;
	stack_trace.nr_entries = 0;
	stack_trace.entries = trace;
	stack_trace.skip = 2;
	save_stack_trace(&stack_trace);
	return stack_trace.nr_entries;
}


/*
 * Look-up a memory block metadata (qkmp_object) in the object search
 * tree based on a pointer value. If alias is 0, only values pointing to the
 * beginning of the memory block are allowed. The qkmp_lock must be held
 * when calling this function.
 */
static struct qkmp_object *lookup_object(unsigned long ptr, int alias)
{
	struct rb_node *rb = object_tree_root.rb_node;

	while (rb) {
		struct qkmp_object *object =
			rb_entry(rb, struct qkmp_object, rb_node);
		if (ptr < object->pointer)
			rb = object->rb_node.rb_left;
		else if (object->pointer + object->size <= ptr)
			rb = object->rb_node.rb_right;
		else if (object->pointer == ptr || alias){
			return object;
        }
		else {
			printk(KERN_INFO"Found object by alias at 0x%08lx\n",
				      ptr);
			break;
		}
	}
	return NULL;
}

static int scan_should_stop(void)
{
	if (!qkmp_enabled)
		return 1;
	return 0;
}

/*
 * RCU callback to free a qkmp_object.
 */
static void free_object_rcu(struct rcu_head *rcu)
{
	struct qkmp_object *object =
		container_of(rcu, struct qkmp_object, rcu);
	kmem_cache_free(object_cache, object);
}

/*
 * Decrement the object use_count. Once the count is 0, free the object using
 * an RCU callback. Since put_object() may be called via the qkmp_free() ->
 * delete_object() path, the delayed RCU freeing ensures that there is no
 * recursive call to the kernel allocator. Lock-less RCU object_list traversal
 * is also possible.
 */
static void put_object(struct qkmp_object *object)
{
	call_rcu(&object->rcu, free_object_rcu);
}

static void __delete_object(struct qkmp_object *object)
{
	unsigned long flags;

	write_lock_irqsave(&qkmp_lock, flags);
	rb_erase(&object->rb_node, &object_tree_root);
	list_del_rcu(&object->object_list);
	write_unlock_irqrestore(&qkmp_lock, flags);

	WARN_ON(!(object->flags & OBJECT_ALLOCATED));
	/*
	 * Locking here also ensures that the corresponding memory block
	 * cannot be freed when it is being scanned.
	 */
	spin_lock_irqsave(&object->lock, flags);
	object->flags &= ~OBJECT_ALLOCATED;
	spin_unlock_irqrestore(&object->lock, flags);
	put_object(object);
}
/*
 * Look up an object in the object search tree and increase its use_count.
 */
static struct qkmp_object *find_and_get_object(unsigned long ptr, int alias)
{
	unsigned long flags;
	struct qkmp_object *object = NULL;

	rcu_read_lock();
	read_lock_irqsave(&qkmp_lock, flags);
	if (ptr >= min_addr && ptr < max_addr)
		object = lookup_object(ptr, alias);
	read_unlock_irqrestore(&qkmp_lock, flags);
	rcu_read_unlock();

	return object;
}

/*
 * Look up the metadata (struct qkmp_object) corresponding to ptr and
 * delete it.
 */
static void delete_object_full(unsigned long ptr)
{
	struct qkmp_object *object;

	object = find_and_get_object(ptr, 1);
	if (!object) {
		return;
	}
	__delete_object(object);
	put_object(object);
}

/*
 * Scan a memory block (exclusive range) for valid pointers and add those
 * found to the gray list.
 */
static void scan_block(void *_start, void *_end,
		       struct qkmp_object *scanned)
{
	unsigned long *ptr;
	unsigned long *start = PTR_ALIGN(_start, BYTES_PER_POINTER);
	unsigned long *end = _end - (BYTES_PER_POINTER - 1);
	unsigned long flags;

    read_lock_irqsave(&qkmp_lock, flags);
	for (ptr = start; ptr < end; ptr++) {
		struct qkmp_object *object;
		unsigned long pointer;

		if (1)
			cond_resched();

		if (scan_should_stop())
			break;

#if 1
		/* don't scan uninitialized memory */
		if (!kmemcheck_is_obj_initialized((unsigned long)ptr,
						  BYTES_PER_POINTER))
			continue;
#endif

		pointer = *ptr;
		//printk(KERN_ERR"[%s]__LINE__=%d,pointer=0x%lx,ptr=0x%p\n",__func__,__LINE__,pointer,ptr);

		if (pointer < min_addr || pointer >= max_addr)
			continue;

		/*
		 * No need for get_object() here since we hold qkmp_lock.
		 * object->use_count cannot be dropped to 0 while the object
		 * is still present in object_tree_root and object_list
		 * (with updates protected by qkmp_lock).
		 */
		object = lookup_object(pointer, 1);
		if (!object)
			continue;

		if (object == scanned)
			/* self referenced, ignore */
			continue;

		/*
		 * Avoid the lockdep recursive warning on object->lock being
		 * previously acquired in scan_object(). These locks are
		 * enclosed by scan_mutex.
		 */
		spin_lock_nested(&object->lock, SINGLE_DEPTH_NESTING);
		if (!color_white(object)) {
			/* non-orphan, ignored or new */
			spin_unlock(&object->lock);
			continue;
		}

		/*
		 * Increase the object's reference count (number of pointers
		 * to the memory block). If this count reaches the required
		 * minimum, the object's color will become gray and it will be
		 * added to the gray_list.
		 */
		object->count++;
		if (color_gray(object)) {
			/* put_object() called when removing from gray_list */
			//WARN_ON(!get_object(object));
			list_add_tail(&object->gray_list, &gray_list);
		}
		spin_unlock(&object->lock);
	}
        read_unlock_irqrestore(&qkmp_lock, flags);
}

/*
 * Scan a large memory block in MAX_SCAN_SIZE chunks to reduce the latency.
 */
static void scan_large_block(void *start, void *end)
{
	void *next;

	while (start < end) {
		next = min(start + MAX_SCAN_SIZE, end);
		scan_block(start, next, NULL);
		start = next;
		cond_resched();
	}
}

static void qkmp_disable(void)
{
	/* stop any memory operation tracing */
	qkmp_enabled = 0;
}


/*
 * Scan data sections and all the referenced memory blocks allocated via the
 * kernel's standard allocators. This function must be called with the
 * scan_mutex held.
 */
static void qkmp_scan(char *buf)
{
	unsigned long flags;
	struct qkmp_object *object;

	jiffies_last_scan = jiffies;

	/* prepare the qkmp_object's */
	rcu_read_lock();
	list_for_each_entry_rcu(object, &object_list, object_list) {
		spin_lock_irqsave(&object->lock, flags);
		/* reset the reference count (whiten the object) */
		object->count = 0;
		if (color_gray(object))
			list_add_tail(&object->gray_list, &gray_list);

		spin_unlock_irqrestore(&object->lock, flags);
	}
	rcu_read_unlock();

//	scan_block((void *)start_addr, (void *)end_addr, NULL);
       scan_large_block((void *)stack_start_addr, (void *)stack_end_addr);
       scan_large_block((void *)static_start_addr, (void *)static_end_addr);

	/*
	 * If scanning was stopped do not report any new unreferenced objects.
	 */
	if (scan_should_stop())
		return;

    return;

}

static struct qkmp_object *create_object(unsigned long ptr, size_t size,
					     int min_count, gfp_t gfp)
{
	unsigned long flags;
	struct qkmp_object *object, *parent;
	struct rb_node **link, *rb_parent;

	object = kmem_cache_alloc(object_cache, gfp_qkmp_mask(gfp));
	if (!object) {
		printk(KERN_ERR"Cannot allocate a qkmp_object structure\n");
		qkmp_disable();
		return NULL;
	}

	INIT_LIST_HEAD(&object->object_list);
	INIT_LIST_HEAD(&object->gray_list);
	INIT_HLIST_HEAD(&object->area_list);
	spin_lock_init(&object->lock);
	atomic_set(&object->use_count, 1);
	object->flags = OBJECT_ALLOCATED;
	object->pointer = ptr;
	object->size = size;
	object->min_count = min_count;
	object->count = 0;			/* white color initially */
	object->jiffies = jiffies;
	object->checksum = 0;

	/* task information */
	if (in_irq()) {
		object->pid = 0;
		strncpy(object->comm, "hardirq", sizeof(object->comm));
	} else if (in_softirq()) {
		object->pid = 0;
		strncpy(object->comm, "softirq", sizeof(object->comm));
	} else {
		object->pid = current->pid;
		/*
		 * There is a small chance of a race with set_task_comm(),
		 * however using get_task_comm() here may cause locking
		 * dependency issues with current->alloc_lock. In the worst
		 * case, the command line is not correct.
		 */
		strncpy(object->comm, current->comm, sizeof(object->comm));
	}

	/* kernel backtrace */
	object->trace_len = __save_stack_trace(object->trace);

	write_lock_irqsave(&qkmp_lock, flags);
	/*These 2 variable is for update the scope when we want to scan the address.
	 * If out of the scope, we can discard it very fast.*/
	min_addr = min(min_addr, ptr);
	max_addr = max(max_addr, ptr + size);

	//printk(KERN_ERR"[%s]__LINE__=%d,max_addr=0x%lx,min_addr=0x%lx\n",__func__,__LINE__,max_addr,min_addr);
	link = &object_tree_root.rb_node;
	rb_parent = NULL;
	while (*link) {
		rb_parent = *link;
		parent = rb_entry(rb_parent, struct qkmp_object, rb_node);
		if (ptr + size <= parent->pointer)
			link = &parent->rb_node.rb_left;
		else if (parent->pointer + parent->size <= ptr)
			link = &parent->rb_node.rb_right;
		else {
			qkmp_stop("Cannot insert 0x%lx into the object "
				      "search tree (overlaps existing)\n",
				      ptr);
			/*
			 * No need for parent->lock here since "parent" cannot
			 * be freed while the qkmp_lock is held.
			 */
			kmem_cache_free(object_cache, object);
			object = NULL;
			goto out;
		}
	}
	rb_link_node(&object->rb_node, rb_parent, link);
	rb_insert_color(&object->rb_node, &object_tree_root);

	list_add_tail_rcu(&object->object_list, &object_list);
out:
	write_unlock_irqrestore(&qkmp_lock, flags);
	return object;
}

static int do_entry_vfree(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    unsigned long ptr= (unsigned long )(regs->di);
    printk(KERN_INFO"[vfree entry]:Ready to free ptr=0x%lx\n",ptr);
    delete_object_full(ptr);
	return 0;
}

static int do_entry_vmalloc(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	/*parameter of vmalloc is DI */
	//printk(KERN_INFO"[entry]:pid:%d|comm:%10s,reg->di=%lu\n",current->pid, current->comm, regs->di);
	malloc_size = (uint32_t)(regs->di);
    printk(KERN_INFO"[vmalloc entry]:malloc size=%d\n",malloc_size);
    //printk(KERN_INFO"[%s]:ip=%lx\n",__func__,regs->ip);
    if (malloc_size){
		return 0;
	}
	return 1;
}

static int do_ret_vmalloc(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	/*ret of vmalloc is ax */
	unsigned long ptr;
	ptr = (unsigned long)(regs->ax);
	if (ptr){
		//FIXME
		//printk(KERN_INFO"[%s]:ip=%lx\n",__func__,regs->ip);
		create_object((unsigned long)ptr, (size_t)malloc_size, MIN_COUNT, GFP_KERNEL);
		//printk(KERN_INFO"[ret]:reg->ax=0x%lx store in the object\n",regs->ax);
	}
	return 0;
}

struct kretprobe vmalloc_qkmp = {
	.handler = do_ret_vmalloc,
	.entry_handler = do_entry_vmalloc,
};

struct kretprobe free_qkmp={
	.entry_handler = do_entry_vfree,
};

static int do_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	int i = 0;
	//printk(KERN_INFO"[pre]:pid:%d|comm:%10s,reg->di=0x%x\n",current->pid, current->comm, regs->di);
	for(i=0;i<index;i++){
		if(p->addr == qkrp_dev[i].qkrp.addr){
				this_cpu = raw_smp_processor_id();
				qkrp_dev[i].pre_t = cpu_clock(this_cpu);
				qkrp_dev[i].pre_nsec= do_div(qkrp_dev[i].pre_t, 1000000000);
		}
	}
	return 0;
}

static void do_post_handler(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
	int i = 0;
	//printk(KERN_INFO"[post]:pid:%d|comm:%10s,reg->di=0x%x\n",current->pid, current->comm, regs->di);
	for(i=0;i<index;i++){
		if(p->addr == qkrp_dev[i].qkrp.addr){
			qkrp_dev[i].cnt++;
			//this_cpu = raw_smp_processor_id();
			qkrp_dev[i].post_t = cpu_clock(this_cpu);
			qkrp_dev[i].post_nsec= do_div(qkrp_dev[i].post_t, 1000000000);
			qkrp_dev[i].cur_duration = qkrp_dev[i].post_nsec-qkrp_dev[i].pre_nsec;
			qkrp_dev[i].total_duration=qkrp_dev[i].total_duration+qkrp_dev[i].cur_duration;
			qkrp_dev[i].avr_duration=(qkrp_dev[i].total_duration)/qkrp_dev[i].cnt;
		}
	}
}
static int do_fault_handler(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
	printk(KERN_INFO"do fault done\n");
	return 0;
}

static ssize_t show_memleaks(struct device *dev,
				     struct device_attribute *attr,
				     char *buf)
{
	unsigned long flags;
    struct qkmp_object *object;
    int ret = 0;
    int new_leaks = 0;
    qkmp_scan(buf);
    if(start_addr < end_addr)
	    scan_large_block((void *)start_addr, (void*)end_addr);
	rcu_read_lock();
	list_for_each_entry_rcu(object, &object_list, object_list) {
		spin_lock_irqsave(&object->lock, flags);
		if (unreferenced_object(object)) {
			new_leaks++;
			ret +=scnprintf(buf+ret, PAGE_SIZE-ret, "<Block addr-0x%lx>:<%s>:<pid-%d>:<trace-0x%lx>\n",
					object->pointer,"May Leak",
					object->pid,
					object->trace[0]);

		}else{
			ret +=scnprintf(buf+ret, PAGE_SIZE-ret, "<Block addr-0x%lx>:<%s>:<pid-%d>:<trace-0x%lx>\n",
					object->pointer,"Not free",
					object->pid,
					object->trace[2]);
		}
		spin_unlock_irqrestore(&object->lock, flags);
	}
	if (new_leaks)
		ret +=scnprintf(buf+ret, PAGE_SIZE-ret, "About %d new memory leaks\n",new_leaks);
    return ret ;
}
static DEVICE_ATTR(memleaks,S_IRUGO, show_memleaks, NULL);

static ssize_t store_scan_start_addr(struct device *dev,
				      struct device_attribute *attr,
				      const char *buf,
				      size_t count)
{
	int ret = 0;
	unsigned long value;
	ret = kstrtoul(buf, 16, &value);
	if(ret < 0){
		return 0;
	}
	sync_start++;
	qkmp_enabled = 0;
	start_addr = (unsigned long )value;
	printk(KERN_INFO"[%s]:start_addr=0x%lx,count=%d\n",__func__,value,(int)count);
	if(sync_start && sync_end && (end_addr > start_addr)){
		//scan_large_block((void *)start_addr, (void*)end_addr);
		qkmp_enabled = 1;
		sync_end = sync_start = 0;
	}
	return count;
}

static ssize_t store_scan_end_addr(struct device *dev,
				      struct device_attribute *attr,
				      const char *buf,
				      size_t count)
{
	int ret = 0;
	unsigned long value;
	ret = kstrtoul(buf, 16, &value);
	if(ret < 0){
		return 0;
	}
	sync_end++;
	end_addr = (unsigned long )value;
    qkmp_enabled = 0;
	printk(KERN_INFO"[%s]:end_addr=0x%lx,count=%d\n",__func__,value, (int)count);
	if(sync_start && sync_end && (end_addr > start_addr)){
		//scan_large_block((void *)start_addr, (void*)end_addr);
		qkmp_enabled = 1;
		sync_end = sync_start = 0;
	}
	return count;
}

static DEVICE_ATTR(scan_end_addr,S_IWUSR, NULL, store_scan_end_addr);
static DEVICE_ATTR(scan_start_addr, S_IWUSR, NULL, store_scan_start_addr);

static struct attribute *dev_scan_attributes[] = {
	&dev_attr_scan_start_addr.attr,
	&dev_attr_scan_end_addr.attr,
	NULL
};

static struct attribute_group dev_scan_addr_group= {
	.attrs = dev_scan_attributes
};

static ssize_t show_qattrs(struct device *dev,
				     struct device_attribute *attr,
				     char *buf)
{
 	int i = 0;
	int ret = 0;
	if(!index)
		return scnprintf(buf, PAGE_SIZE, "Please input right func,when you insmod\n");
	for(i=0; i<index;i++){
		ret +=scnprintf(buf+ret, PAGE_SIZE-ret, "%s:%lu<ns>:%lu<cnt>\n",qkrp_dev[i].name,
																	qkrp_dev[i].avr_duration,
																	qkrp_dev[i].cnt
																	);
	}
	return ret;
}

static ssize_t store_qattrs(struct device *dev,
				      struct device_attribute *attr,
				      const char *buf,
				      size_t count)
{
	int ret = 0;
	return ret;
}

static DEVICE_ATTR(qattrs, S_IWUSR | S_IRUGO,
		show_qattrs, store_qattrs);


static const struct file_operations qeexo_device_fops = {
	.owner		= THIS_MODULE,
};

static char *p5;
static char *p6;
static char *p7;
static void vmalloc_test2(void )
{
	p5 = vmalloc(30);
	p6 = vmalloc(30);
	printk(KERN_INFO"[%s]p5=0x%p,p6=0x%p\n",__func__,p5,p6);
	printk(KERN_INFO"[%s]&p5=0x%p,&p6=0x%p\n",__func__,&p5,&p6);
	static_start_addr=(unsigned long)&p5;
	static_end_addr=(unsigned long)&p7;
	qkmp_enabled = 1;

}

static void vmalloc_test1(void )
{
	char *p0 = vmalloc(10);
	char *p1 = vmalloc(20);
	char *p2 = vmalloc(30);
	char *p3 = vmalloc(30);
	char *p4;

	printk(KERN_INFO"[%s]p0=0x%p,p1=0x%p,p2=0x%p,p3=%p\n",__func__,p0,p1,p2,p3);
	printk(KERN_INFO"[%s]&p=0x%p,&p1=0x%p,&p2=0x%p.&p3=0x%p\n",__func__,&p0,&p1,&p2,&p3);
	vfree(p2);
	stack_start_addr=(unsigned long)&p0;
	stack_end_addr=(unsigned long)&p4;
	qkmp_enabled = 1;
}

static int __init qkrp_init(void)
{
	int ret;
	int i = 0;
	struct device *dev;
	char *func_name=NULL;
	char *funcs_name = kstrdup(funcs, GFP_KERNEL);
	char *bak_p= funcs_name;
/*register the krp*/
	while(funcs_name && !strncmp("sys", funcs_name, 3)){
		func_name = strsep(&funcs_name, ",");
		if(!strncmp("sys", func_name, 3)){
			qkrp_dev[index].qkrp.addr = (kprobe_opcode_t *)kallsyms_lookup_name(func_name);
			if(qkrp_dev[index].qkrp.addr == NULL) goto err_exit;
			qkrp_dev[index].qkrp.pre_handler = do_pre_handler;
			qkrp_dev[index].qkrp.post_handler= do_post_handler;
			qkrp_dev[index].qkrp.fault_handler= do_fault_handler;

			qkrp_dev[index].id = index;
			qkrp_dev[index].cnt = 0;
			qkrp_dev[index].total_duration = 0;
			qkrp_dev[index].cur_duration = 0;
			qkrp_dev[index].avr_duration= 0;
			strncpy(qkrp_dev[index].name, func_name, strlen(func_name));
			printk(KERN_ERR"[%s]system call name=%s\n",__func__,qkrp_dev[index].name);

		}else{
			printk(KERN_ERR"For stable, we just profile the sys_XXX\n");
			goto err_exit;
		}
		ret = register_kprobe(&(qkrp_dev[index].qkrp));
		if( ret < 0 ){
			printk(KERN_ERR"register kprobe qkrp %d error\n",index);
			goto err_exit;
		}
		index++;
	}
	object_cache = KMEM_CACHE(qkmp_object, SLAB_NOLEAKTRACE);
/*register the kmp*/
	vmalloc_qkmp.kp.addr = (kprobe_opcode_t *)kallsyms_lookup_name("vmalloc");
	if(vmalloc_qkmp.kp.addr == NULL) {
		printk(KERN_ERR"Vmalloc kprobe failed\n");
		goto err_exit;
	}
	free_qkmp.kp.addr = (kprobe_opcode_t *)kallsyms_lookup_name("vfree");
	if(free_qkmp.kp.addr == NULL) {
		printk(KERN_ERR"Vfree kprobe failed\n");
		goto err_exit;
	}

	ret = register_kretprobe(&(vmalloc_qkmp));
	if( ret < 0 ){
		printk(KERN_ERR"register kprobe malloc error\n");
		goto err_exit;
	}

	ret = register_kretprobe(&(free_qkmp));
	if( ret < 0 ){
		printk(KERN_ERR"register kprobe vfree error\n");
		goto err_exit;
	}

	kfree(bak_p);

	major= register_chrdev(0, "qeexo", &qeexo_device_fops);
	if (major < 0) {
		printk(KERN_ERR"failed to register qeexo device (%d)\n", major);
		goto err_exit_kprob;
	}

	qeexo_class = class_create(THIS_MODULE, "qeexo");
	if (IS_ERR(qeexo_class)) {
		ret = PTR_ERR(qeexo_class);
		goto err_exit_chrdev;
	}
	/* not a big deal if we fail here :-) */
	dev = device_create(qeexo_class, NULL, MKDEV(major, 0), NULL, "profiler");
	if(dev == NULL){
		printk(KERN_ERR"create deice error\n");
		goto err_exit_class;
	}

	ret = device_create_file(dev, &dev_attr_qattrs);
	if(ret < 0){
		printk(KERN_ERR"create qattrs file error\n");
		goto err_exit_device;
	}
	ret = device_create_file(dev, &dev_attr_memleaks);
	if(ret < 0){
		printk(KERN_ERR"create memleaks file error\n");
		goto err_exit_device;
	}
	ret = sysfs_create_group(&dev->kobj, &dev_scan_addr_group);
	if(ret < 0){
		printk(KERN_ERR"create scan group error\n");
		goto err_exit_device;
	}

	printk(KERN_INFO"%s is done\n",__func__);
/*ADD test code*/
   vmalloc_test1();
   vmalloc_test2();

	return 0;
err_exit_device:
	device_destroy(qeexo_class, MKDEV(major, 0));
err_exit_class:
	class_unregister(qeexo_class);
err_exit_chrdev:
	unregister_chrdev(major, "qeexo");
err_exit_kprob:
	for(i=0;i<index;i++){
		unregister_kprobe(&(qkrp_dev[i].qkrp));
	}
err_exit:
	printk(KERN_INFO"register kprobe qkrp error\n");
	return 0;
}

static void __exit qkrp_exit(void)
{
	int i = 0;
	unregister_kretprobe(&(vmalloc_qkmp));
	unregister_kretprobe(&(free_qkmp));
	device_destroy(qeexo_class, MKDEV(major, 0));
	class_unregister(qeexo_class);
	unregister_chrdev(major, "qkrp");
	for(i=0;i<index;i++){
		unregister_kprobe(&(qkrp_dev[i].qkrp));
	}
	printk(KERN_INFO"unregister kprobe qkrp done\n");
}

module_init(qkrp_init);
module_exit(qkrp_exit);
