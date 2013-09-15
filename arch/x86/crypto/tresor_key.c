/*
 * TRESOR password prompt and key derivation
 *
 * Copyright (C) 2010 Tilo Mueller <tilo.mueller@informatik.uni-erlangen.de>
 * Copyright (C) 2012 Hans Spath <tresor@hans-spath.de>
 * Copyright (C) 2012 Johannes Goetzfried <johannes@jgoetzfried.de>
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
#include <stdarg.h>

int term_fd;
unsigned char key_hash[32];

/* SHA256 Macros */
#define	rot(x, n)	(((x) >> n) | ((x) << (32 - n)))
#define	shr(x, n)	(((x) >> n))
#define s0(x)		(rot(x,  7) ^ rot(x, 18) ^ shr(x,  3))
#define s1(x)		(rot(x, 17) ^ rot(x, 19) ^ shr(x, 10))
#define S0(x)		(rot(x,  2) ^ rot(x, 13) ^ rot(x, 22))
#define S1(x)		(rot(x,  6) ^ rot(x, 11) ^ rot(x, 25))
#define ch(x, y, z)	(((x) & (y)) ^ ((~x) & (z)))
#define maj(x, y, z)	(((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define endian(x)	(((x)>>24) | ((x)>>8 & 0x0000FF00) |\
			 ((x)<<24) | ((x)<<8 & 0x00FF0000))

/* SHA256 Constants */
static const uint32_t k[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
	0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
	0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
	0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
	0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
	0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
	0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
	0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
	0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
	0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/*
 * Key derivation function: SHA-256.
 *
 * About key strenthening: Unfortunately, there is no easy way to store a salt
 * value on disk early during boot. We can only increase the number of SHA-256
 * iterations to strengthen the key.
 *
 * So use safe passwords / passphrases for TRESOR. All printable ASCII chars are
 * allowed and passwords are only restricted to 53 chars.
 *
 * Paramter:
 *	- message:  A max. 53 char's long message.
 *		    (more characters are just ignored)
 *	- digest:   A 32 char's long array, where the
 *		    message digest is stored.
 */
static void sha256(const char *message, int msglen, unsigned char *digest)
{
	     int i;
	 uint8_t chunk[64];
	uint32_t w[64];
	uint32_t a, b, c, d, e, f, g, h;
	uint32_t t1, t2;
	uint32_t *hash = (uint32_t *) digest;

	/* Restrict to 53 characters */
	msglen = (msglen > 53) ? 53 : msglen;

	/* Pre-processing: Build chunk[] */
	for (i = 0; i < msglen; i++)
		chunk[i] = message[i];
	chunk[i++] = 0x80;
	for (; i < 62; i++)
		chunk[i] = 0x00;
	for (; i < 64; i++)
		chunk[i] = (uint8_t)(msglen*8 >> (63-i)*8);

	/* Build w[]: Extend 16 dwords to 64 dwords */
	for (i = 0; i < 16; i++)
		w[i] =	chunk[i*4+0] << 24 |
			chunk[i*4+1] << 16 |
			chunk[i*4+2] <<  8 |
			chunk[i*4+3] ;
	for (i = 16; i < 64; i++)
		w[i] =	     w[i - 16]
			+ s0(w[i - 15])
			+    w[i - 7]
			+ s1(w[i - 2]);

	/* Initialize hash value of the chunk */
	hash[0] = 0x6a09e667;	a = hash[0];
	hash[1] = 0xbb67ae85;	b = hash[1];
	hash[2] = 0x3c6ef372;	c = hash[2];
	hash[3] = 0xa54ff53a;	d = hash[3];
	hash[4] = 0x510e527f;	e = hash[4];
	hash[5] = 0x9b05688c;	f = hash[5];
	hash[6] = 0x1f83d9ab;	g = hash[6];
	hash[7] = 0x5be0cd19;	h = hash[7];

	/* Main loop */
	for (i = 0; i < 64; i++) {
		t1 = h + S1(e) + ch(e, f, g) + k[i] + w[i];
		t2 = S0(a) + maj(a, b, c);
		h = g; g = f;
		f = e; e = d + t1;
		d = c; c = b;
		b = a; a = t1 + t2;
	}

	/* Add the chunks hash to the result */
	hash[0] += a; hash[1] += b;
	hash[2] += c; hash[3] += d;
	hash[4] += e; hash[5] += f;
	hash[6] += g; hash[7] += h;

	/* Align endian */
	hash[0] = endian(hash[0]); hash[1] = endian(hash[1]);
	hash[2] = endian(hash[2]); hash[3] = endian(hash[3]);
	hash[4] = endian(hash[4]); hash[5] = endian(hash[5]);
	hash[6] = endian(hash[6]); hash[7] = endian(hash[7]);

	/* Reset critical memory locations */
	msglen = 0; t1 = 0; t2 = 0;
	a = 0; b = 0; c = 0; d = 0;
	e = 0; f = 0; g = 0; h = 0;
	memset(chunk, 0, 64);
	memset(w, 0, 64);
	wbinvd();
}

#ifdef CONFIG_CRYPTO_TRESOR_PROMPT
/* Print to term_fd */
static int printf_(const char *fmt, ...)
{
	va_list args; int col = 80; char line[col];

	va_start(args, fmt);
	vsnprintf(line, col, fmt, args);
	line[col-1] = 0;
	va_end(args);

	return sys_write(term_fd, line, strlen(line));
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
int tresor_readkey(const char *terminal, int resume)
{
	unsigned char password[54], key[32], key_hash_[32], answer[4], c;
	struct termios termios;
	mm_segment_t ofs;
	int i, j, progress;

	/* prepare to call systemcalls from kernelspace */
	ofs = get_fs();
	set_fs(get_ds());
	/* try to open terminal */
	term_fd = sys_open(terminal, O_RDWR, 0);
	if (term_fd < 0) {
		set_fs(ofs);
		return term_fd;
	}
	/* read single characters; no echo */
	sys_ioctl(term_fd, TCGETS, (long)&termios);
	termios.c_lflag &= ~(ICANON | ECHO);
	sys_ioctl(term_fd, TCSETSF, (long)&termios);
	/* initialize console */
	cursor_enable();
	cls();

readkey:
	/* Read password */
	printf("\n >> TRESOR <<");
	i = 0;
	printf("\n\n Enter password  \t> ");
	while (1) {
		c = getchar();

		/* Backspace */
		if (i > 0 && (c == 0x7f || c == 0x08)) {
			printf_("\b \b");
			i--;
		}

		/* Printable character */
		else if (i < 53 && (c >= 0x20 && c <= 0x7E)) {
			printf_("*");
			password[i++] = c;
		}

		/* Cancel */
		else if (c == 0x03 || c == 0x18) {
			for (; i > 0; i--)
				printf_("\b \b");
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
	sha256(password, strlen(password), key);
	for (i = 0; i < TRESOR_KDF_ITER; i++) {
		sha256(key, 32, key_hash_);
		sha256(key_hash_, 32, key);
	}
	tresor_setkey(key);
	sha256(key, 32, key_hash_);
	/* Reset critical memory chunks */
	c = 0;
	memset(password, 0, 54);
	memset(key, 0, 32);
	wbinvd();
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

	/* clean up */
	sys_close(term_fd);
	set_fs(ofs);
	return 0;
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
	sha256(password, strlen(password), key);
	for (i = 0; i < TRESOR_KDF_ITER; i++) {
		sha256(key, 32, key_hash);
		sha256(key_hash, 32, key);
	}
	tresor_setkey(key);
	sha256(key, 32, key_hash);
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
	sha256(key, 32, key_hash);
	memset(key, 0, 32);

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
