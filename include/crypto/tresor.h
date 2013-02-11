#ifndef _CRYPTO_TRESOR_H
#define _CRYPTO_TRESOR_H

#include <linux/crypto.h>
#include <linux/types.h>

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
#endif

#ifdef CONFIG_CRYPTO_TRESOR_KEYDEVICE
/* Get key device */
struct block_device* tresor_dev_wait(void);

/* Read the first 512 bytes from the given 512-byte sector on bdev into the given page */
int tresor_read_keydevice_sector(struct block_device *bdev, sector_t sector, struct page *page);
#endif

#ifndef CONFIG_CRYPTO_MANAGER_DISABLE_TESTS
/* Prevent the test manager from overwriting dbg regs with test keys */
void tresor_unlock_tests(void);
void tresor_lock_tests(void);
int tresor_lock_status(void);
#endif

#endif /* _CRYPTO_TRESOR_H */
