#ifndef _CRYPTO_TRESOR_H
#define _CRYPTO_TRESOR_H

#include <linux/crypto.h>
#include <linux/types.h>
#include <linux/blkdev.h>

/* maximum passphrase length */
#define TRESOR_MAX_PASSWORD_LENGTH 54

/* number of iterations for key derivation */
#define TRESOR_KDF_ITER 2000

/* number of chars to clear memory */
#define TRESOR_RANDOM_CHARS 4096

/* TRESOR core functionality (enc, dec, setkey) */
void tresor_encrypt(struct crypto_tfm *tfm, u8 *dst, const u8 *src);
void tresor_decrypt(struct crypto_tfm *tfm, u8 *dst, const u8 *src);
// Used to notify that we have gone to sleep (ie key disappeared)
void tresor_notify_keyunset(void);
void tresor_setkey(const u8 *in_key);
bool tresor_capable(void);

#ifdef CONFIG_CRYPTO_TRESOR_PROMPT
/* Password prompt */
int  tresor_readkey(int resume);

/* Key prompt on wakeup after suspend2ram */
void tresor_dont_switch_console(int dont_switch);
void tresor_thaw_processes(void);

/* Optional mode in shamir's sharing where you can type an additional hex char (so you can split existing keys)
   (NOTE: strictly 1/0, not >1)
 */
extern unsigned char tresor_shamirs_compat;
#endif

#ifdef CONFIG_CRYPTO_TRESOR_KEYDEVICE
/* The maximum number of keydevices which can be used */
#define TRESOR_MAX_KEY_DEVICES 10

/* Contains the block_device* pointer and name which was used to find this block device */
struct tresor_device_and_name {
	struct block_device* dev;
	char* name;
};

/* Get next key device. Returns a struct with dev = NULL if no key devices are needed */
struct tresor_device_and_name tresor_next_dev_wait(char tresor_devices_used[]);

/* Read the first 512 bytes from the given 512-byte sector on bdev into the given page */
int tresor_read_keydevice_sector(struct block_device *bdev, sector_t sector, struct page *page);

/* The number of sharedevices required, 0 indicates one non-shamirs device */
extern int tresor_shares_required;
#endif

#ifndef CONFIG_CRYPTO_MANAGER_DISABLE_TESTS
/* Prevent the test manager from overwriting dbg regs with test keys */
void tresor_unlock_tests(void);
void tresor_lock_tests(void);
int tresor_lock_status(void);
#endif

#endif /* _CRYPTO_TRESOR_H */
