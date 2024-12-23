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
#include "aesd_ioctl.h"

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
    size_t bytes_left = 0;
    size_t copy_size = 0;

    PDEBUG("read %zu bytes with offset %lld", count, *f_pos);

    if (mutex_lock_interruptible(&dev->mutex)) {
        return -ERESTARTSYS;
    }

    entry = aesd_circular_buffer_find_entry_offset_for_fpos(&dev->circbuf, *f_pos, &offset_out);
    if (entry == NULL) {
        PDEBUG("Failed to find entry!");
        mutex_unlock(&dev->mutex);
        return 0;
    }
    mutex_unlock(&dev->mutex);

    // Clamp the copy size if the user is requesting less
    bytes_left = entry->size - offset_out;
    copy_size = (bytes_left > count) ? count : bytes_left;

    PDEBUG("Reading %zu bytes. offset_out: %zu", copy_size, offset_out);
	if (copy_to_user(buf, entry->buffptr + offset_out, copy_size)) {
        PDEBUG("Failed to copy_to_user!");
		retval = -EFAULT;
	}
    *f_pos += copy_size;
    retval = copy_size;

    return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos)
{
    struct aesd_dev *dev = filp->private_data;
    const char *replaced_entry;
    char *e_ptr;

    PDEBUG("write %zu bytes with offset %lld. Value: '%s'", count, *f_pos, buf);

    if (mutex_lock_interruptible(&dev->mutex)) {
        PDEBUG("Failed to obtain lock!");
        return -ERESTARTSYS;
    }

    // Create a temp entry (krealloc behaves like kmalloc when buffptr is NULL)
    PDEBUG("Allocating %zu bytes.", dev->tmp_entry.size + count);
    e_ptr = krealloc(dev->tmp_entry.buffptr, dev->tmp_entry.size + count, GFP_KERNEL);
    if (e_ptr == NULL) {
        PDEBUG("Failed to malloc!");
        // If we have existing allocations then free
        if (dev->tmp_entry.buffptr != NULL) {
            kfree(dev->tmp_entry.buffptr);
            dev->tmp_entry.buffptr = NULL;
            dev->tmp_entry.size = 0;
        }
        mutex_unlock(&dev->mutex);
        return -ENOMEM;
    }

    // Copy users write data into temp entry
    if (copy_from_user(e_ptr + dev->tmp_entry.size, buf, count)) {
        // If we have existing allocations then free
        PDEBUG("Failed to copy_from_user!");
        if (dev->tmp_entry.buffptr != NULL) {
            kfree(dev->tmp_entry.buffptr);
            dev->tmp_entry.buffptr = NULL;
            dev->tmp_entry.size = 0;
        }
        mutex_unlock(&dev->mutex);
        return -EFAULT;
    }

    // Update temp entry
    dev->tmp_entry.buffptr = e_ptr;
    dev->tmp_entry.size += count;
    PDEBUG("Temp Entry stats: buffptr: %p, size: %zu", dev->tmp_entry.buffptr, dev->tmp_entry.size);
    // If there is a newline then the entry is complete, write it to the circular buffer
    if (strchr(buf, '\n')) {
        PDEBUG("Adding new entry!");
        replaced_entry = aesd_circular_buffer_add_entry(&dev->circbuf, &dev->tmp_entry);
        // If the circular buffer dropped the oldest entry, then free it here
        if (replaced_entry != NULL) {
            PDEBUG("Freeing old entry!");
            kfree(replaced_entry);
        }

        // Reset temp entry since circular buffer is now tracking that data
        dev->tmp_entry.buffptr = NULL;
        dev->tmp_entry.size = 0;
    }

    mutex_unlock(&dev->mutex);
    return count;
}

/**
 * @brief  Adjust the file offset (f_pos) parameter of @param filp based on the location specified by 
 *         @param write_cmd (the zero referenced command to locate) and @param write_cmd_offset
 *         (the zero referenced offset into the command)
 * @return 0 if successful, negative if error occurred:
 *             -ERESTARTSYS if mutex could not be obtained
 *             -EINVAL if write command or write_cmd_offset was out of range 
 */
static long aesd_adjust_file_offset(struct file *filp, unsigned int write_cmd, unsigned int write_cmd_offset)
{
    // Write command: command/data to seek to within the circular buffer, zero referenced
    // write_cmd_offset: The zero referenced offset within this command to seek into. All offsets are specified relative to the start of the request.
    // For instance, if the offset was 2 in the command “Grass”, the seek location should be the letter “a”

    // Check for valid write_cmd and write_cmd_offset values
        // Invalid things:
        // When a specified command hasn't been written yet (doesn't exist in the buffer)
        // out of range command. Our buffer only holds 10 commands (example: 11)
        // write_cmd_offset is >= size of command
        // If invalid then return -EINVAL
    // Calculate the start offset to write_cmd
        // Add the length of each write between the output pointer and write_cmd
    // And then add write_cmd_offset to give you the total file position inside the circular buffer.
    // Save as filp->f_pos
    return 0;
}

long int aesd_ioctl(struct file *filp, unsigned int request, unsigned long arg)
{
    struct aesd_dev *dev = filp->private_data;
    int retval = 0;

    PDEBUG("aesd_ioctl: request: %ld", request);

    switch (request)
    {
        case AESDCHAR_IOCSEEKTO:
        {
            PDEBUG("aesd_ioctl: AESDCHAR_IOCSEEKTO");
            struct aesd_seekto seekto;
            if (copy_from_user(&seekto, (const void __user *)arg, sizeof(seekto)) != 0) {
                retval = EFAULT;
            } else {
                retval = aesd_adjust_file_offset(filp, seekto.write_cmd, seekto.write_cmd_offset);
            }
        }
        break;
        default:
            retval = -ENOTTY;
        break;
    }

    return retval;
}

loff_t aesd_llseek(struct file *filp, loff_t offset, int whence)
{
    PDEBUG("aesd_llseek: Offset: %lld, Whence: %d.", offset, whence);
    struct aesd_dev *dev = filp->private_data;

    mutex_lock(&dev->mutex);
    loff_t tot_size = aesd_get_size_of_all_entries(&dev->circbuf);
    PDEBUG("aesd_llseek: Total circular buffer size: %lld", tot_size);
    loff_t ret = fixed_size_llseek(filp, offset, whence, tot_size);
    PDEBUG("aesd_llseek: ret value: %lld", ret);
    mutex_unlock(&dev->mutex);

    return ret;
}

struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .unlocked_ioctl = aesd_ioctl,
    .llseek =   aesd_llseek,
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
