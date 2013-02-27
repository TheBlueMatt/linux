/*
 * TRESOR password prompt and key derivation
 *
 * Copyright (C) 2010 Tilo Mueller <tilo.mueller@informatik.uni-erlangen.de>
 * Copyright (C) 2012 Hans Spath <tresor@hans-spath.de>
 * Copyright (C) 2012 Johannes Goetzfried <johannes@jgoetzfried.de>
 * Copyright (C) 2013 Matt Corallo <tresor@mattcorallo.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */

#include <crypto/tresor.h>
#include <crypto/hash.h>
#include <linux/fd.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/kbd_kern.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/oom.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/sysfs.h>
#include <linux/tty.h>
#include <linux/fs.h>
#include <linux/delay.h>
#include <stdarg.h>

int fds[11]; // /dev/console + /dev/tty[0-9]
int term_fd;
unsigned char key_hash[32];

/*
 * Key derivation function: SHA-256.
 *
 * About key strenthening: It is recommended you use a random key device as well
 * as just a passphrase to provide more input to the hash.  Currently, it only
 * reads 512 bytes off the key device, but if you're reading this, you should go
 * change that to make you happy.
 *
 * So use safe passwords / passphrases for TRESOR.
 */
static struct crypto_shash* tfm = NULL;
static struct shash_desc* desc = NULL;
static int desc_size;
static int prepare_sha256(void)
{
	tfm = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	desc_size = sizeof(struct shash_desc) + crypto_shash_descsize(tfm);
	desc = kmalloc(desc_size, GFP_KERNEL);
	if (!desc)
		return PTR_ERR(desc);
	desc->tfm = tfm;
	desc->flags = 0;

	return 0;
}

static void free_sha256(void)
{
	if (desc != NULL) {
		memset(desc, 0, desc_size);
		wbinvd();
		kfree(desc);
		desc = NULL;
	}
	if (tfm != NULL) {
		crypto_free_shash(tfm);
		tfm = NULL;
	}
}

/*
 * Paramter:
 *	- message:  A message.
 *	- digest:   A 32 char's long array, where the
 *		    message digest is stored.
 */
static int sha256(const char *message, int msglen, unsigned char *digest)
{
	int ret = 0;

	ret = crypto_shash_init(desc);
	if (ret < 0)
		goto error;

	ret = crypto_shash_finup(desc, message, msglen, digest);
	if (ret < 0)
		goto error;

	return 0;

error:
	memset(digest, 0, 32);
	wbinvd();
	return ret;
}

#ifdef CONFIG_CRYPTO_TRESOR_PROMPT
/* Print to appropriate fd.
 * This means either everything or term_fd
 */
static int printf_(const char *fmt, ...)
{
	va_list args; int ret = -1, col = 80; char line[col]; int* term = fds;

	va_start(args, fmt);
	vsnprintf(line, col, fmt, args);
	line[col-1] = 0;
	va_end(args);

	if (term_fd >= 0) {
		ret = sys_write(term_fd, line, strlen(line));
	} else {
		while (term < fds + 11) {
			if (*term >= 0) {
				ret = sys_write(*term, line, strlen(line));
				if (unlikely(!ret))
					return ret;
			}
			term++;
		}
	}
	return ret;
}

/* Erase line before printing (workaround for weird consoles) */
static int printf(const char *fmt, ...)
{
	va_list args; int res;

	printf_("\x1B[0G");
	va_start(args, fmt);
	res = printf_(fmt, args);
	va_end(args);

	return res;
}

/* sets term_fd to the fd which the user is actually using */
static void setterm_fd(void)
{
	unsigned char c; int* term = fds;

	/* First clear all input buffers, as sometimes we get ghost input... */
	while (term < fds + 11) {
		while (*term >= 0 && sys_read(*term, &c, 1) == 1) ;
		term++;
	}

	/* Now wait for actual input */
	term_fd = 0;
	/* We use a really horrible, ugly loop here because select() doesn't work in kernel */
	while (term_fd == 0) {
		term = fds;
		while (term < fds + 11) {
			if (*term >= 0 && sys_read(*term, &c, 1) == 1) {
				term_fd = *term;
				break;
			}
			term++;
		}
		msleep(50);
	}
}

/* Read from term_fd */
static unsigned char getchar(void)
{
	unsigned char c;
	sys_read(term_fd, &c, 1);
	return c;
}

/* Clear term_fd */
static int cls(void)
{
	int i;
	i  = printf_("\n");
	i += printf_("\x1B[2J");
	i += printf_("\x1B[100A");
	return i;
}

/* Disables the cursor of term_fd */
static void cursor_disable(void)
{
	printf_("\x1B[?1c");
}

/* Enables the cursor of term_fd */
static void cursor_enable(void)
{
	printf_("\x1B[?6c");
}

/* Resets the cursor of term_fd to default */
static void cursor_reset(void)
{
	printf_("\x1B[?0c");
}

/*
 * Password prompt
 *
 * Returns an error code smaller zero if the terminal
 * cannot be opened and zero otherwise.
 */
int tresor_readkey(int resume)
{
	unsigned char password[54], key[32], key_hash_[32], answer[4], c, ret = 0;
	struct termios termios;
	mm_segment_t ofs;
	int i, j, progress;
	int* term;

#ifdef CONFIG_CRYPTO_TRESOR_KEYDEVICE
	struct page* keydevice_page = NULL;
	unsigned char* keydevice_key = NULL;
	sector_t keydevice_sector;
	struct block_device* keydevice_dev;
#endif

	/* prepare to call systemcalls from kernelspace */
	ofs = get_fs();
	set_fs(get_ds());

	/* try to open terminal */
	term_fd = 0;
	fds[0] = sys_open("/dev/console", O_RDWR|O_NONBLOCK, 0);
	fds[1] = sys_open("/dev/tty0", O_RDWR|O_NONBLOCK, 0);
	fds[2] = sys_open("/dev/tty1", O_RDWR|O_NONBLOCK, 0);
	fds[3] = sys_open("/dev/tty2", O_RDWR|O_NONBLOCK, 0);
	fds[4] = sys_open("/dev/tty3", O_RDWR|O_NONBLOCK, 0);
	fds[5] = sys_open("/dev/tty4", O_RDWR|O_NONBLOCK, 0);
	fds[6] = sys_open("/dev/tty5", O_RDWR|O_NONBLOCK, 0);
	fds[7] = sys_open("/dev/tty6", O_RDWR|O_NONBLOCK, 0);
	fds[8] = sys_open("/dev/tty7", O_RDWR|O_NONBLOCK, 0);
	fds[9] = sys_open("/dev/tty8", O_RDWR|O_NONBLOCK, 0);
	fds[10] = sys_open("/dev/tty9", O_RDWR|O_NONBLOCK, 0);
	ret = fds[0];
	term = fds;
	while (term < fds + 11) {
		if (*term >= 0) {
			ret = *term;
			break;
		}
		term++;
	}
	if (ret < 0) {
		set_fs(ofs);
		return ret;
	}
	ret = 0;

	/* Clear the screen and ask for input on all consoles */
	printf("\n >> TRESOR <<");
	// The trailing \n on the next line is to make sure other terminals aren't left in a weird state
	printf("\n Press enter to initialize input\n");

	/* Find the console the user is on and clear O_NONBLOCK */
	setterm_fd();
	sys_fcntl(term_fd, F_SETFL, 0);

	/* read single characters; no echo */
	sys_ioctl(term_fd, TCGETS, (long)&termios);
	termios.c_lflag &= ~(ICANON | ECHO);
	sys_ioctl(term_fd, TCSETSF, (long)&termios);

	/* initialize console */
	cursor_enable();
	/* re-clear screen because this sometimes makes everything visible
	 * (the user can hit enter blind, but its cool if they can see this next part)
	 */
	cls();

readkey:
	/* Read password */
	printf("\n >> TRESOR <<");

#ifdef CONFIG_CRYPTO_TRESOR_KEYDEVICE
	printf("\n Waiting on keydevice(s) to appear.");
	printf("\n If boot hangs here, make sure your modules are built-in.");
	keydevice_dev = tresor_dev_wait();
	if (keydevice_dev) {
		keydevice_page = alloc_page(GFP_KERNEL);
		if (unlikely(!keydevice_page)) {
			ret = -ENOMEM;
			goto closeret;
		}
		keydevice_key = (unsigned char*)page_address(keydevice_page);
		if (unlikely(!keydevice_key)) {
			ret = -ENOMEM;
			goto closeret;
		}

		printf("\n\n Enter keydevice read offset (in sectors)  \t> ");

		i = 0;
		while (1) {
			c = getchar();

			/* Backspace */
			if (i > 0 && (c == 0x7f || c == 0x08)) {
				//printf_("\b \b");
				i--;
			}

			/* Digit */
			else if (i < 15 && (c >= '0' && c <= '9')) {
				//printf_("%c", c);
				password[i++] = c;
			}

			/* Cancel */
			else if (c == 0x03 || c == 0x18) {
				//for (; i > 0; i--)
				//	printf_("\b \b");
				i = 0;
			}

			/* Enter */
			else if (c == 0x04 || c == 0x0a || c == 0x0b ||
				 c == 0x0c || c == 0x0d) {
				if (i < 1)
					continue;
				for (; i < 16; i++)
					password[i] = 0x0;
				keydevice_sector = simple_strtoull(password, NULL, 10);
				if (tresor_read_keydevice_sector(keydevice_dev, keydevice_sector, keydevice_page)) {
					i = 0;
					printf("\n Failed to read at given offset, try again  > ");
					continue;
				}
				break;
			}
		}
	} else {
		printf("\n\n Not using a keydevice.");
	}
#endif

	i = 0;
	printf("\n\n Enter password (minimum 8 characters)  \t> ");
	while (1) {
		c = getchar();

		/* Backspace */
		if (i > 0 && (c == 0x7f || c == 0x08)) {
			//printf_("\b \b");
			i--;
		}

		/* Printable character */
		else if (i < 53 && (c >= 0x20 && c <= 0x7E)) {
			//printf_("*");
			password[i++] = c;
		}

		/* Cancel */
		else if (c == 0x03 || c == 0x18) {
			//for (; i > 0; i--)
			//	printf_("\b \b");
			i = 0;
		}

		/* Enter */
		else if (c == 0x04 || c == 0x0a || c == 0x0b ||
			 c == 0x0c || c == 0x0d) {
			if (i < 8)
				continue;
			for (; i < 54; i++)
				password[i] = 0x0;
			break;
		}
	}

	/* derivate and set key */
	prepare_sha256();
#ifdef CONFIG_CRYPTO_TRESOR_KEYDEVICE
	if (keydevice_dev) {
		memcpy(keydevice_key+512, password, strlen(password));
		sha256(keydevice_key, 512+strlen(password), key);
	} else
#endif
	sha256(password, strlen(password), key);
	for (i = 0; i < TRESOR_KDF_ITER; i++) {
		sha256(key, 32, key_hash_);
		sha256(key_hash_, 32, key);
	}
	tresor_setkey(key);
	sha256(key, 32, key_hash_);
	free_sha256();

	/* Reset critical memory chunks */
	c = 0;
	memset(password, 0, sizeof(password));
	memset(key, 0, 32);
#ifdef CONFIG_CRYPTO_TRESOR_KEYDEVICE
	if (keydevice_dev) {
		keydevice_sector = 0;
		memset(keydevice_key, 0, PAGE_SIZE);
	}
#endif
	wbinvd();

#ifdef CONFIG_CRYPTO_TRESOR_KEYDEVICE
	if (keydevice_dev)
		__free_page(keydevice_page);
#endif

	if (resume) {
		/* Check if key is the same as before suspending */
		if (memcmp(key_hash, key_hash_, 32)) {
			printf("\n\n Sorry, the key you entered is wrong or mistyped.");
			schedule_timeout_uninterruptible(1*HZ);
			printf_(".");
			schedule_timeout_uninterruptible(1*HZ);
			printf_(".");
			schedule_timeout_uninterruptible(1*HZ);
			goto readkey;
		}
	} else {
		/* Store hash of the key and show user */
		memcpy(key_hash, key_hash_, 32);
		printf("\n\n Confirm key hash\t> ");
		for (i = 0; i < 16; i++)
			printf_("%02x ", key_hash[i]);
		printf("\n                 \t  ");
		for (i = 16; i < 32; i++)
			printf_("%02x ", key_hash[i]);

		/* Let user confirm correct key */
		printf("\n\n Correct (yes/no) \t> ");

		printf_("yes");
		answer[0] = 'y'; answer[1] = 'e';
		answer[2] = 's'; answer[3] =  0 ;
		i = 3;
		while (1) {
			c = getchar();

			/* Backspace */
			if (i > 0 && (c == 0x7f || c == 0x08)) {
				printf_("\b \b");
				answer[--i] = 0;
			}

			/* Letter */
			else if (i < 3 && (c >= 0x61 && c <= 0x7a)) {
				printf_("%c", c);
				answer[i++] = c;
			}

			/* Cancel */
			else if (c == 0x03 || c == 0x18) {
				for (; i > 0; i--)
					printf_("\b \b");
			}

			/* Enter */
			else if (c == 0x04 || c == 0x0a ||
				 c == 0x0b || c == 0x0c || c == 0x0d) {
				answer[i] = 0;
				if (!strcmp(answer, "no"))
					goto readkey;
				else if (!strcmp(answer, "yes"))
					break;
				continue;
			}
		}
	}

	/* read some key strokes */
	printf("\n\n");

	for (i = 0; i < TRESOR_RANDOM_CHARS; i++) {
		progress = (i * 40) / TRESOR_RANDOM_CHARS;

		printf_("\r Press or hold any key \t[");
		for (j = 0; j < progress - 1; j++)
			printf_("=");
		if (progress)
			printf_(">");
		for (j += 2; j < 40; j++)
			printf_(" ");
		printf_("]  %d%%", ((i + 1) * 100) / TRESOR_RANDOM_CHARS);

		getchar();
	}

	/* restore terminal */
	if (resume)
		cls();
	else
		printf("\n\n");

	termios.c_lflag |= (ICANON | ECHO);
	sys_ioctl(term_fd, TCSETSF, (long)&termios);

	if (resume)
		cursor_disable();
	else
		cursor_reset();

closeret:
	/* clean up */
	term = fds;
	while (term < fds + 11) {
		if (*term >= 0)
			sys_close(*term);
		term++;
	}
	if (keydevice_dev)
		blkdev_put(keydevice_dev, FMODE_READ);
	set_fs(ofs);
	return ret;
}
#endif

#ifdef CONFIG_CRYPTO_TRESOR_SYSFS
#ifndef CONFIG_CRYPTO_MANAGER_DISABLE_TESTS
/*
 * Functions to lock or unlock the tresor tests in the testmanager
 */
static ssize_t lock_show(struct kobject *kobj, struct kobj_attribute *attr,
			 char *buf)
{
	return sprintf(buf, "%d\n", tresor_lock_status());
}

static ssize_t lock_store(struct kobject *kobj, struct kobj_attribute *attr,
			  const char *buf, size_t count)
{
	int val = -1;

	if (sscanf(buf, "%d", &val) != 1)
		return -EINVAL;

	if (val == 1)
		tresor_lock_tests();
	else if (val == 0)
		tresor_unlock_tests();
	else
		return -EINVAL;

	return count;
}

static struct kobj_attribute lock_attribute =
	__ATTR(lock, 0600, lock_show, lock_store);
#endif


/*
 * Show the SHA256 hash of the key currently in use
 */
static ssize_t hash_show(struct kobject *kobj, struct kobj_attribute *attr,
			 char *buf)
{
	ssize_t ret = 0;
	unsigned int i;

	ret = sprintf(&buf[ret], "Key hash:\n");
	for (i = 0; i < 16; i++)
		ret += sprintf(&buf[ret], "%02x ", key_hash[i]);
	ret += sprintf(&buf[ret], "\n");
	for (i = 16; i < 32; i++)
		ret += sprintf(&buf[ret], "%02x ", key_hash[i]);
	ret += sprintf(&buf[ret], "\n");

	return ret;
}

/*
 * Set the key using key derivation with SHA256
 */
static ssize_t password_store(struct kobject *kobj, struct kobj_attribute *attr,
			      const char *buf, size_t count)
{
	unsigned char password[54], key[32];
	unsigned int i;

	memcpy(password, buf, 54);
	password[53] = '\0';

	/* derivate and set key */
	prepare_sha256();
	sha256(password, strlen(password), key);
	for (i = 0; i < TRESOR_KDF_ITER; i++) {
		sha256(key, 32, key_hash);
		sha256(key_hash, 32, key);
	}
	tresor_setkey(key);
	sha256(key, 32, key_hash);
	free_sha256();
	/* Reset critical memory chunks */
	memset(password, 0, 54);
	memset(key, 0, 32);

	/* Reset the input buffer (ugly hack) */
	memset((char *)buf, 0, count);

	return count;
}

static struct kobj_attribute password_attribute =
	__ATTR(password, 0600, hash_show, password_store);


/*
 * Set the key directly using hex values
 */
static ssize_t key_store(struct kobject *kobj, struct kobj_attribute *attr,
			 const char *buf, size_t count)
{
	uint8_t key[32];

	if (count < 64 || hex2bin(key, buf, 32) < 0)
		return -EINVAL;

	tresor_setkey(key);
	prepare_sha256();
	sha256(key, 32, key_hash);
	memset(key, 0, 32);
	free_sha256();

	/* Reset the input buffer (ugly hack) */
	memset((char *)buf, 0, count);

	return count;
}

static struct kobj_attribute key_attribute =
	__ATTR(key, 0600, hash_show, key_store);


static struct attribute *attrs[] = {
#ifndef CONFIG_CRYPTO_MANAGER_DISABLE_TESTS
	&lock_attribute.attr,
#endif
	&password_attribute.attr,
	&key_attribute.attr,
	NULL
};

static struct attribute_group attr_group = {
	.attrs = attrs,
};

static struct kobject *tresor_kobj;


static int __init tresor_init(void)
{
	int ret;

	tresor_kobj = kobject_create_and_add("tresor", kernel_kobj);
	if (!tresor_kobj)
		return -ENOMEM;

	ret = sysfs_create_group(tresor_kobj, &attr_group);
	if (ret)
		kobject_put(tresor_kobj);

	return ret;
}

static void __exit tresor_fini(void)
{
	kobject_put(tresor_kobj);
}

module_init(tresor_init);
module_exit(tresor_fini);
#endif
