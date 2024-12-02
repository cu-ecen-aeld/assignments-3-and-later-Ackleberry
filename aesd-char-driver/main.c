/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h> // file_operations
#include "aesdchar.h"

int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("Ackleberry");
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

int aesd_open(struct inode *inode, struct file *filp)
{
    struct aesd_dev *dev;

    PDEBUG("open");
    /**
     * TODO: handle open
     */

    /* inode->i_cdev points to cdev in aesd_device object. By giving the struct and member we can 
       find the base address of this object. */
    dev = container_of(inode->i_cdev, struct aesd_dev, cdev);
    filp->private_data = dev; /* For other methods */

    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    /**
     * TODO: handle release
     */
    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = 0;
    struct aesd_dev *dev = filp->private_data;
    struct aesd_buffer_entry *entry;
    size_t entry_offset = 0;
    size_t offset_out = 0;

    PDEBUG("read %zu bytes with offset %lld", count, *f_pos);

    if (*f_pos != 0) {
        return 0;
    }

    entry = aesd_circular_buffer_find_entry_offset_for_fpos(&dev->circbuf, entry_offset, &offset_out);
    PDEBUG("Reading %zu bytes. Value: '%s'", entry->size, entry->buffptr);
	if (copy_to_user(buf, entry->buffptr, entry->size)) {
		retval = -EFAULT;
	}
    *f_pos += entry->size;
    retval = entry->size;

    return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = -ENOMEM;
    struct aesd_dev *dev = filp->private_data;
    struct aesd_buffer_entry *entry_ptr;
    char *entry_buf;
    PDEBUG("write %zu bytes with offset %lld. Value: '%s'", count, *f_pos, buf);
    /**
     * TODO: handle write
     */

    // Allocate kernel memory to hold the user data
    entry_buf = kmalloc(count, GFP_KERNEL);
    if (!entry_buf)
        return -ENOMEM;

    // Copy data from user space to kernel space
    if (copy_from_user(entry_buf, buf, count)) {
        kfree(entry_buf);
        return -EFAULT;
    }

    entry_ptr = kmalloc(sizeof(struct aesd_buffer_entry), GFP_KERNEL);
    entry_ptr->buffptr = entry_buf;
    entry_ptr->size = count;
    aesd_circular_buffer_add_entry(&dev->circbuf, entry_ptr);
    retval = count;

    return retval;
}
struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add (&dev->cdev, devno, 1);
    if (err) {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}



int aesd_init_module(void)
{
    dev_t dev = 0;
    int result = alloc_chrdev_region(&dev, aesd_minor, 1, "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device, 0, sizeof(struct aesd_dev));

    /**
     * TODO: initialize the AESD specific portion of the device  
     */
    aesd_circular_buffer_init(&aesd_device.circbuf);

    result = aesd_setup_cdev(&aesd_device);
    if (result) {
        unregister_chrdev_region(dev, 1);
    }
    return result;

}

void aesd_cleanup_module(void)
{
    dev_t devno = MKDEV(aesd_major, aesd_minor);

    cdev_del(&aesd_device.cdev);

    /**
     * TODO: cleanup AESD specific poritions here as necessary
     */

    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
