/*
Copyright (c) 2015, Intel Corporation. All rights reserved.
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
#include <linux/spinlock.h>
#include <linux/rwsem.h>
#include <linux/stddef.h>
#include <linux/device.h>
#include <linux/mutex.h>
#include <linux/slab.h>

#include <linux/hrtimer.h>
#include <linux/tick.h>
#include <linux/times.h>
#include <linux/vmalloc.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("hui");
MODULE_DESCRIPTION("QKRP module");

static char *funcs = "test";
module_param(funcs,charp,0644);

#define QKRP_MAJOR	3333
#define MAX_NUM 20
static int major = QKRP_MAJOR;
static struct class *qkrp_class;
extern unsigned long volatile jiffies;
static uint8_t index = 0;
int this_cpu;

/*attrs*/
uint32_t qattrs;
uint32_t memleaks;

/*Below parameters is about memleak*/
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
static DEFINE_RWLOCK(kmemleak_lock);

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


#if 0
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

	read_lock_irqsave(&kmemleak_lock, flags);
	for (ptr = start; ptr < end; ptr++) {
		struct qkmp_object *object;
		unsigned long pointer;

		if (scan_should_stop())
			break;

		/* don't scan uninitialized memory */
		if (!kmemcheck_is_obj_initialized((unsigned long)ptr,
						  BYTES_PER_POINTER))
			continue;

		kasan_disable_current();
		pointer = *ptr;
		kasan_enable_current();

		if (pointer < min_addr || pointer >= max_addr)
			continue;

		/*
		 * No need for get_object() here since we hold kmemleak_lock.
		 * object->use_count cannot be dropped to 0 while the object
		 * is still present in object_tree_root and object_list
		 * (with updates protected by kmemleak_lock).
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
			WARN_ON(!get_object(object));
			list_add_tail(&object->gray_list, &gray_list);
		}
		spin_unlock(&object->lock);
	}
	read_unlock_irqrestore(&kmemleak_lock, flags);
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
#endif

static struct qkmp_object *create_object(unsigned long ptr, size_t size,
					     int min_count, gfp_t gfp)
{
	unsigned long flags;
	struct qkmp_object *object, *parent;
	struct rb_node **link, *rb_parent;

	object = kmem_cache_alloc(object_cache, gfp_kmemleak_mask(gfp));
	if (!object) {
		pr_warning("Cannot allocate a qkmp_object structure\n");
		kmemleak_disable();
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

	write_lock_irqsave(&kmemleak_lock, flags);

	min_addr = min(min_addr, ptr);
	max_addr = max(max_addr, ptr + size);
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
			kmemleak_stop("Cannot insert 0x%lx into the object "
				      "search tree (overlaps existing)\n",
				      ptr);
			/*
			 * No need for parent->lock here since "parent" cannot
			 * be freed while the kmemleak_lock is held.
			 */
			dump_object_info(parent);
			kmem_cache_free(object_cache, object);
			object = NULL;
			goto out;
		}
	}
	rb_link_node(&object->rb_node, rb_parent, link);
	rb_insert_color(&object->rb_node, &object_tree_root);

	list_add_tail_rcu(&object->object_list, &object_list);
out:
	write_unlock_irqrestore(&kmemleak_lock, flags);
	return object;
}



static int test_pre(struct kprobe *p, struct pt_regs *regs)
{
	int i = 0;
	printk(KERN_INFO"[testpre]:pid:%d|comm:%10s,reg->di=%lu\n",current->pid, current->comm, regs->di);
	printk(KERN_INFO"[testpre]:reg->ax=0x%lx\n",regs->ax);
	printk(KERN_INFO"[testpre]:reg->di=0x%lx\n",regs->di);
	printk(KERN_INFO"[testpre]:reg->dx=0x%lx\n",regs->dx);
	return 0;
}

static void test_post(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
	int i = 0;
	printk(KERN_INFO"[testpost]:pid:%d|comm:%10s,reg->di=%lu\n",current->pid, current->comm, regs->di);
	printk(KERN_INFO"[testpost]:reg->ax=0x%lx\n",regs->ax);
	printk(KERN_INFO"[testpost]:reg->di=0x%lx\n",regs->di);
	printk(KERN_INFO"[testpost]:reg->dx=0x%lx\n",regs->dx);

}
static int test_fault(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
	printk(KERN_INFO"do fault done\n");
	return 0;
}

struct kprobe test_qkmp = {
	.pre_handler = test_pre,
	.post_handler= test_post,
	.fault_handler= test_fault,
};

static int do_ret_vfree(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	//printk(KERN_INFO"[post]:pid:%d|comm:%10s,reg->di=%lu\n",current->pid, current->comm, regs->di);
	return 0;
}
static int do_entry_vmalloc(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	/*parameter of vmalloc is DI */
	printk(KERN_INFO"[entry]:pid:%d|comm:%10s,reg->di=%lu\n",current->pid, current->comm, regs->di);
	size = (uint32_t *)(regs->di);
	if (size){
		return 0;
	}
	return 1;
}

static int do_ret_vmalloc(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	/*ret of vmalloc is ax */
	//printk(KERN_INFO"[ret]:pid:%d|comm:%10s,reg->di=%lu\n",current->pid, current->comm, regs->di);
	printk(KERN_INFO"[ret]:reg->ax=0x%lx\n",regs->ax);
	printk(KERN_INFO"[ret]:reg->di=0x%lx\n",regs->di);
	printk(KERN_INFO"[ret]:reg->dx=0x%lx\n",regs->dx);
	unsigned long long *ptr= regs->ax;
	if ( ptr && !IS_ERR(ptr)){
		create_object((unsigned long)ptr, size, min_count);
	}
	return 0;
}

struct kretprobe vmalloc_qkmp = {
	.handler = do_ret_vmalloc,
	.entry_handler = do_entry_vmalloc,
};

struct kretprobe free_qkmp={
	.handler = do_ret_vfree,
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
#if 0
			printk(KERN_INFO"pre[%5lu,%7lu],post[%5lu,%7lu],cur_duration=%lu,avr_duration=%lu\n",
												(unsigned long)qkrp_dev[i].pre_t,qkrp_dev[i].pre_nsec,
												(unsigned long)qkrp_dev[i].post_t,qkrp_dev[i].post_nsec,
												qkrp_dev[i].cur_duration,qkrp_dev[i].avr_duration);
#endif
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
	return 0;
}
static DEVICE_ATTR(memleaks,S_IRUGO, show_memleaks, NULL);

static ssize_t store_scan_start_addr(struct device *dev,
				      struct device_attribute *attr,
				      const char *buf,
				      size_t count)
{
	int ret = 0;
	return ret;
}

static ssize_t store_scan_end_addr(struct device *dev,
				      struct device_attribute *attr,
				      const char *buf,
				      size_t count)
{
	int ret = 0;
	return ret;
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


static const struct file_operations qkrp_device_fops = {
	.owner		= THIS_MODULE,
};


static int __init qkrp_init(void)
{
	int ret;
	int i = 0;
	struct device *dev;
	char *func_name=NULL;
	char *funcs_name = kstrdup(funcs, GFP_KERNEL);
	char *bak_p= funcs_name;
	while(funcs_name && !strncmp("sys", funcs_name, 3)){
		func_name = strsep(&funcs_name, ",");
		if(!strncmp("sys", func_name, 3)){
			qkrp_dev[index].qkrp.addr = (kprobe_opcode_t *)kallsyms_lookup_name(func_name);
			if(qkrp_dev[index].qkrp.addr == NULL) goto err_exit;
			//printk(KERN_INFO "func_name=%s,addr=0x%x\n",func_name,qkrp_dev[index].qkrp.addr);
			qkrp_dev[index].qkrp.pre_handler = do_pre_handler;
			qkrp_dev[index].qkrp.post_handler= do_post_handler;
			qkrp_dev[index].qkrp.fault_handler= do_fault_handler;

			qkrp_dev[index].id = index;
			qkrp_dev[index].cnt = 0;
			qkrp_dev[index].total_duration = 0;
			qkrp_dev[index].cur_duration = 0;
			qkrp_dev[index].avr_duration= 0;
			strncpy(qkrp_dev[index].name, func_name, strlen(func_name));
			printk(KERN_ERR"name=%s\n",qkrp_dev[index].name);

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
/*register the kmp*/
#ifdef TEST
	test_qkmp.addr = (kprobe_opcode_t *)kallsyms_lookup_name("vmalloc");
	if(test_qkmp.addr == NULL) {
		printk(KERN_ERR"Vmalloc kprobe failed\n");
		goto err_exit;
	}
	ret = register_kprobe(&(test_qkmp));
	if( ret < 0 ){
		printk(KERN_ERR"register kprobe test error\n");
		goto err_exit;
	}
#else
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
#endif

	kfree(bak_p);

	major= register_chrdev(0, "qkrp", &qkrp_device_fops);
	if (major < 0) {
		printk(KERN_ERR"failed to register qkrp device (%d)\n", major);
		goto err_exit_kprob;
	}

	qkrp_class = class_create(THIS_MODULE, "qkrp");
	if (IS_ERR(qkrp_class)) {
		ret = PTR_ERR(qkrp_class);
		goto err_exit_chrdev;
	}
	/* not a big deal if we fail here :-) */
	dev = device_create(qkrp_class, NULL, MKDEV(major, 0), NULL, "qkrp");
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

/*ADD test code*/
	char *p = vmalloc(10);
	char *p1 = vmalloc(20);
	char *p2 = vmalloc(30);
	printk(KERN_INFO"p=0x%p,p1=0x%p,p2=0x%p\n",p,p1,p2);
	printk(KERN_INFO"register kprobe qkrp done\n");
	return 0;
err_exit_device:
	device_destroy(qkrp_class, MKDEV(major, 0));
err_exit_class:
	class_unregister(qkrp_class);
err_exit_chrdev:
	unregister_chrdev(major, "qkrp");
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
#ifdef TEST
	unregister_kretprobe(&(test_qkmp));
#else
	unregister_kretprobe(&(vmalloc_qkmp));
	unregister_kretprobe(&(free_qkmp));
#endif
	device_destroy(qkrp_class, MKDEV(major, 0));
	class_unregister(qkrp_class);
	unregister_chrdev(major, "qkrp");
	for(i=0;i<index;i++){
		unregister_kprobe(&(qkrp_dev[i].qkrp));
	}
	printk(KERN_INFO"unregister kprobe qkrp done\n");
}

module_init(qkrp_init);
module_exit(qkrp_exit);
