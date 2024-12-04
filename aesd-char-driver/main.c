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
#include <linux/string.h>
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

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos)
{
    ssize_t retval = 0;
    struct aesd_dev *dev = filp->private_data;
    struct aesd_buffer_entry *entry;
    size_t offset_out = 0;

    PDEBUG("read %zu bytes with offset %lld", count, *f_pos);

    if (mutex_lock_interruptible(&aesd_device.mutex)) {
        return -ERESTARTSYS;
    }

    entry = aesd_circular_buffer_find_entry_offset_for_fpos(&dev->circbuf, *f_pos, &offset_out);
    if (entry == NULL) {
        mutex_unlock(&aesd_device.mutex);
        return 0;
    }
    mutex_unlock(&aesd_device.mutex);

    PDEBUG("Reading %zu bytes. Value: '%s'", entry->size, entry->buffptr);
	if (copy_to_user(buf, entry->buffptr, entry->size)) {
		retval = -EFAULT;
	}
    *f_pos += entry->size;
    retval = entry->size;

    return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos)
{
    struct aesd_dev *dev = filp->private_data;
    const char *replaced_entry;
    char *e_ptr;

    PDEBUG("write %zu bytes with offset %lld. Value: '%s'", count, *f_pos, buf);

    if (mutex_lock_interruptible(&aesd_device.mutex)) {
        return -ERESTARTSYS;
    }

    // Create a temp entry (krealloc behaves like kmalloc when buffptr is NULL)
    e_ptr = krealloc(dev->tmp_entry.buffptr, dev->tmp_entry.size + count, GFP_KERNEL);
    if (e_ptr == NULL) {
        // If we have existing allocations then free
        if (dev->tmp_entry.buffptr != NULL) {
            kfree(dev->tmp_entry.buffptr);
            dev->tmp_entry.buffptr = NULL;
            dev->tmp_entry.size = 0;
        }
        mutex_unlock(&aesd_device.mutex);
        return -ENOMEM;
    }

    // Copy users write data into temp entry
    if (copy_from_user(e_ptr + dev->tmp_entry.size, buf, count)) {
        // If we have existing allocations then free
        if (dev->tmp_entry.buffptr != NULL) {
            kfree(dev->tmp_entry.buffptr);
            dev->tmp_entry.buffptr = NULL;
            dev->tmp_entry.size = 0;
        }
        mutex_unlock(&aesd_device.mutex);
        return -EFAULT;
    }

    // Update temp entry
    dev->tmp_entry.buffptr = e_ptr;
    dev->tmp_entry.size += count;

    // If there is a newline then the entry is complete, write it to the circular buffer
    if (strchr(buf, '\n')) {
        replaced_entry = aesd_circular_buffer_add_entry(&dev->circbuf, &dev->tmp_entry);
        // If the circular buffer dropped the oldest entry, then free it here
        if (replaced_entry != NULL) {
            kfree(replaced_entry);
        }

        // Reset temp entry since circular buffer is now tracking that data
        dev->tmp_entry.buffptr = NULL;
        dev->tmp_entry.size = 0;
    }

    mutex_unlock(&aesd_device.mutex);
    return count;
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
    err = cdev_add(&dev->cdev, devno, 1);
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

    /**
     * TODO: initialize the AESD specific portion of the device  
     */
    memset(&aesd_device, 0, sizeof(struct aesd_dev));
    mutex_init(&aesd_device.mutex);

    aesd_device.tmp_entry.buffptr = NULL;
    aesd_device.tmp_entry.size = 0;
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
