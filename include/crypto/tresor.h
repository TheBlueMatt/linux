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
void tresor_setkey(const u8 *in_key);
bool tresor_capable(void);

#ifdef CONFIG_CRYPTO_TRESOR_PROMPT
/* Password prompt */
int  tresor_readkey(const char *device, int resume);

/* Key prompt on wakeup after suspend2ram */
void tresor_dont_switch_console(int dont_switch);
void tresor_thaw_processes(void);
#endif

#ifndef CONFIG_CRYPTO_MANAGER_DISABLE_TESTS
/* Prevent the test manager from overwriting dbg regs with test keys */
void tresor_unlock_tests(void);
void tresor_lock_tests(void);
int tresor_lock_status(void);
#endif

#endif /* _CRYPTO_TRESOR_H */
