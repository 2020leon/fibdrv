#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kdev_t.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include "bignum.h"

#include "fibdrv.h"

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("National Cheng Kung University, Taiwan");
MODULE_DESCRIPTION("Fibonacci engine driver");
MODULE_VERSION("0.1");

#define DEV_FIBONACCI_NAME "fibonacci"

/* MAX_LENGTH is set to 92 because
 * ssize_t can't fit the number > 92
 */
// #define MAX_LENGTH 92
#define MAX_LENGTH 368

#define clz(x) __builtin_clzll(x)

static dev_t fib_dev = 0;
static struct cdev *fib_cdev;
static struct class *fib_class;
static DEFINE_MUTEX(fib_mutex);

static enum fibdrv_mode mode = FIBDRV_BIGNUM_FAST;
static ktime_t duration;

static ssize_t bignum_fast_wrapper(struct file *file,
                                   char *buf,
                                   size_t size,
                                   loff_t *offset);
static ssize_t bignum_orig_wrapper(struct file *file,
                                   char *buf,
                                   size_t size,
                                   loff_t *offset);
static ssize_t ll_fast_wrapper(struct file *file,
                               char *buf,
                               size_t size,
                               loff_t *offset);
static ssize_t ll_orig_wrapper(struct file *file,
                               char *buf,
                               size_t size,
                               loff_t *offset);
static ssize_t time_wrapper(struct file *file,
                            char *buf,
                            size_t size,
                            loff_t *offset);

static ssize_t (*wrapper[FIBDRV_MODE_SIZE])(struct file *,
                                            char *,
                                            size_t,
                                            loff_t *) = {
    bignum_fast_wrapper, bignum_orig_wrapper, ll_fast_wrapper, ll_orig_wrapper,
    time_wrapper};

static void fib_bignum_fast(long long k, struct bignum *result)
{
    if (!result)
        return;
    if (k <= 1) {
        bignum_from_int(result, k);
        return;
    }
    struct bignum a, b;
    bignum_from_int(&a, 0);
    bignum_from_int(&b, 1);
    for (int mask = 1 << (sizeof(long long) * 8 - 1 - clz(k)); mask > 0;
         mask >>= 1) {
        struct bignum t;
        bignum_shl1(&b, &t, 0);
        bignum_sub(&t, &a, &t);
        bignum_mul(&t, &a, &t);

        bignum_mul(&b, &b, &b);
        bignum_mul(&a, &a, &a);
        bignum_add(&a, &b, &b);

        a = t;
        if (k & mask) {
            bignum_add(&a, &b, &t);
            a = b;
            b = t;
        }
    }
    *result = a;
}

static ssize_t bignum_fast_wrapper(struct file *file,
                                   char *buf,
                                   size_t size,
                                   loff_t *offset)
{
    ktime_t kt = ktime_get();
    if (size >= sizeof(struct bignum)) {
        struct bignum fib;
        fib_bignum_fast(*offset, &fib);
        unsigned long tmp = copy_to_user(buf, &fib, sizeof(fib));
        duration = ktime_sub(ktime_get(), kt);
        return tmp != 0 ? -1 : sizeof(fib);
    }
    duration = -1;
    return -1;
}

static void fib_bignum_orig(long long k, struct bignum *result)
{
    if (!result)
        return;
    if (k <= 1) {
        bignum_from_int(result, k);
        return;
    }
    struct bignum a, b;
    bignum_from_int(&a, 0);
    bignum_from_int(&b, 1);
    while (k > 1) {
        bignum_add(&a, &b, result);
        a = b;
        b = *result;
        k--;
    }
}

static ssize_t bignum_orig_wrapper(struct file *file,
                                   char *buf,
                                   size_t size,
                                   loff_t *offset)
{
    ktime_t kt = ktime_get();
    if (size >= sizeof(struct bignum)) {
        struct bignum fib;
        fib_bignum_orig(*offset, &fib);
        unsigned long tmp = copy_to_user(buf, &fib, sizeof(fib));
        duration = ktime_sub(ktime_get(), kt);
        return tmp != 0 ? -1 : sizeof(fib);
    }
    duration = -1;
    return -1;
}

static long long fib_ll_fast(long long k)
{
    if (k <= 1)
        return k;
    long long a = 0, b = 1;
    for (int mask = 1 << (sizeof(long long) * 8 - 1 - clz(k)); mask > 0;
         mask >>= 1) {
        long long t1 = a * (2 * b - a);
        b = b * b + a * a;
        a = t1;
        if (k & mask) {
            t1 = a + b;
            a = b;
            b = t1;
        }
    }
    return a;
}

static ssize_t ll_fast_wrapper(struct file *file,
                               char *buf,
                               size_t size,
                               loff_t *offset)
{
    ktime_t kt = ktime_get();
    if (size >= sizeof(long long)) {
        long long result = fib_ll_fast(*offset);
        unsigned long tmp = copy_to_user(buf, &result, sizeof(long long));
        duration = ktime_sub(ktime_get(), kt);
        return tmp != 0 ? -1 : sizeof(long long);
    }
    duration = -1;
    return -1;
}


static long long fib_ll_orig(long long k)
{
    long long a = 0, b = 1;
    if (k <= 1)
        return k;
    for (long long i = k; i > 1; i--) {
        k = a + b;
        a = b;
        b = k;
    }
    return k;
}

static ssize_t ll_orig_wrapper(struct file *file,
                               char *buf,
                               size_t size,
                               loff_t *offset)
{
    ktime_t kt = ktime_get();
    if (size >= sizeof(long long)) {
        long long result = fib_ll_orig(*offset);
        unsigned long tmp = copy_to_user(buf, &result, sizeof(long long));
        duration = ktime_sub(ktime_get(), kt);
        return tmp != 0 ? -1 : sizeof(long long);
    }
    duration = -1;
    return -1;
}

static ssize_t time_wrapper(struct file *file,
                            char *buf,
                            size_t size,
                            loff_t *offset)
{
    if (size >= sizeof(ktime_t)) {
        if (copy_to_user(buf, &duration, sizeof(ktime_t)) != 0)
            return -1;
        return sizeof(ktime_t);
    }
    return -1;
}

static int fib_open(struct inode *inode, struct file *file)
{
    if (!mutex_trylock(&fib_mutex)) {
        printk(KERN_ALERT "fibdrv is in use");
        return -EBUSY;
    }
    return 0;
}

static int fib_release(struct inode *inode, struct file *file)
{
    mutex_unlock(&fib_mutex);
    return 0;
}

/* calculate the fibonacci number at given offset */
static ssize_t fib_read(struct file *file,
                        char *buf,
                        size_t size,
                        loff_t *offset)
{
    return wrapper[mode](file, buf, size, offset);
}

/* write operation is skipped */
static ssize_t fib_write(struct file *file,
                         const char *buf,
                         size_t size,
                         loff_t *offset)
{
    if (size == sizeof(mode) && *(enum fibdrv_mode *) buf < FIBDRV_MODE_SIZE) {
        if (copy_from_user(&mode, buf, sizeof(mode)) != 0)
            return -1;
    } else
        mode = FIBDRV_BIGNUM_FAST;
    return 1;
}

static loff_t fib_device_lseek(struct file *file, loff_t offset, int orig)
{
    loff_t new_pos = 0;
    switch (orig) {
    case 0: /* SEEK_SET: */
        new_pos = offset;
        break;
    case 1: /* SEEK_CUR: */
        new_pos = file->f_pos + offset;
        break;
    case 2: /* SEEK_END: */
        new_pos = MAX_LENGTH - offset;
        break;
    }

    if (new_pos > MAX_LENGTH)
        new_pos = MAX_LENGTH;  // max case
    if (new_pos < 0)
        new_pos = 0;        // min case
    file->f_pos = new_pos;  // This is what we'll use now
    return new_pos;
}

const struct file_operations fib_fops = {
    .owner = THIS_MODULE,
    .read = fib_read,
    .write = fib_write,
    .open = fib_open,
    .release = fib_release,
    .llseek = fib_device_lseek,
};

static int __init init_fib_dev(void)
{
    int rc = 0;

    mutex_init(&fib_mutex);

    // Let's register the device
    // This will dynamically allocate the major number
    rc = alloc_chrdev_region(&fib_dev, 0, 1, DEV_FIBONACCI_NAME);

    if (rc < 0) {
        printk(KERN_ALERT
               "Failed to register the fibonacci char device. rc = %i",
               rc);
        return rc;
    }

    fib_cdev = cdev_alloc();
    if (fib_cdev == NULL) {
        printk(KERN_ALERT "Failed to alloc cdev");
        rc = -1;
        goto failed_cdev;
    }
    fib_cdev->ops = &fib_fops;
    rc = cdev_add(fib_cdev, fib_dev, 1);

    if (rc < 0) {
        printk(KERN_ALERT "Failed to add cdev");
        rc = -2;
        goto failed_cdev;
    }

    fib_class = class_create(THIS_MODULE, DEV_FIBONACCI_NAME);

    if (!fib_class) {
        printk(KERN_ALERT "Failed to create device class");
        rc = -3;
        goto failed_class_create;
    }

    if (!device_create(fib_class, NULL, fib_dev, NULL, DEV_FIBONACCI_NAME)) {
        printk(KERN_ALERT "Failed to create device");
        rc = -4;
        goto failed_device_create;
    }
    return rc;
failed_device_create:
    class_destroy(fib_class);
failed_class_create:
    cdev_del(fib_cdev);
failed_cdev:
    unregister_chrdev_region(fib_dev, 1);
    return rc;
}

static void __exit exit_fib_dev(void)
{
    mutex_destroy(&fib_mutex);
    device_destroy(fib_class, fib_dev);
    class_destroy(fib_class);
    cdev_del(fib_cdev);
    unregister_chrdev_region(fib_dev, 1);
}

module_init(init_fib_dev);
module_exit(exit_fib_dev);
