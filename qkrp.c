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


MODULE_LICENSE("GPL");
MODULE_AUTHOR("hui");
MODULE_DESCRIPTION("QKRP module");

static char *funcs = "test";
module_param(funcs,charp,0644);

#define QKRP_MAJOR	3333
static int major = QKRP_MAJOR;
static struct class *qkrp_class;
extern unsigned long volatile jiffies;
#define MAX_NUM 20
static uint8_t index = 0;

/*attrs*/
uint32_t qattrs;
uint32_t memleaks;
//uint32_t scan_start_addr;
//uint32_t scan_end_addr;

static struct qdev_s{
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
} qdev[MAX_NUM];

int this_cpu;
static int do_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	int i = 0;
	for(i=0;i<index;i++){
		if(p->addr == qdev[i].qkrp.addr){
				this_cpu = raw_smp_processor_id();
				qdev[i].pre_t = cpu_clock(this_cpu);
				qdev[i].pre_nsec= do_div(qdev[i].pre_t, 1000000000);
		}
	}
	return 0;
}

static void do_post_handler(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
	int i = 0;
	for(i=0;i<index;i++){
		if(p->addr == qdev[i].qkrp.addr){
			qdev[i].cnt++;
			//this_cpu = raw_smp_processor_id();
			qdev[i].post_t = cpu_clock(this_cpu);
			qdev[i].post_nsec= do_div(qdev[i].post_t, 1000000000);
			qdev[i].cur_duration = qdev[i].post_nsec-qdev[i].pre_nsec;
			qdev[i].total_duration=qdev[i].total_duration+qdev[i].cur_duration;
			qdev[i].avr_duration=(qdev[i].total_duration)/qdev[i].cnt;
#if 0
			printk(KERN_INFO"pre[%5lu,%7lu],post[%5lu,%7lu],cur_duration=%lu,avr_duration=%lu\n",
												(unsigned long)qdev[i].pre_t,qdev[i].pre_nsec,
												(unsigned long)qdev[i].post_t,qdev[i].post_nsec,
												qdev[i].cur_duration,qdev[i].avr_duration);
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
		ret +=scnprintf(buf+ret, PAGE_SIZE-ret, "%s:%lu<ns>:%lu<cnt>\n",qdev[i].name,
																	qdev[i].avr_duration,
																	qdev[i].cnt
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
			qdev[index].qkrp.addr = (kprobe_opcode_t *)kallsyms_lookup_name(func_name);
			if(qdev[index].qkrp.addr == NULL) goto err_exit;
			//printk(KERN_INFO "func_name=%s,addr=0x%x\n",func_name,qdev[index].qkrp.addr);
			qdev[index].qkrp.pre_handler = do_pre_handler;
			qdev[index].qkrp.post_handler= do_post_handler;
			qdev[index].qkrp.fault_handler= do_fault_handler;

			qdev[index].id = index;
			qdev[index].cnt = 0;
			qdev[index].total_duration = 0;
			qdev[index].cur_duration = 0;
			qdev[index].avr_duration= 0;
			strncpy(qdev[index].name, func_name, strlen(func_name));
			printk(KERN_ERR"name=%s\n",qdev[index].name);

		}else{
			printk(KERN_ERR"For stable, we just profile the sys_XXX\n");
			goto err_exit;
		}
		ret = register_kprobe(&(qdev[index].qkrp));
		if( ret < 0 ){
			printk(KERN_ERR"register kprobe qkrp %d error\n",index);
			goto err_exit;
		}
		index++;
	}

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
		unregister_kprobe(&(qdev[i].qkrp));
	}
err_exit:
	printk(KERN_INFO"register kprobe qkrp error\n");
	return 0;
}

static void __exit qkrp_exit(void)
{
	int i = 0;
	device_destroy(qkrp_class, MKDEV(major, 0));
	class_unregister(qkrp_class);
	unregister_chrdev(major, "qkrp");
	for(i=0;i<index;i++){
		unregister_kprobe(&(qdev[i].qkrp));
	}
	printk(KERN_INFO"unregister kprobe qkrp done\n");
}

module_init(qkrp_init);
module_exit(qkrp_exit);
