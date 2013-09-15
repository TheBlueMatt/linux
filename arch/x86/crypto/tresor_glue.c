/*
 * Cold boot resistant AES for 64-bit machines with AES-NI support
 * (currently all Core-i5/7 processors and some Core-i3)
 *
 * Copyright (C) 2010	Tilo Mueller <tilo.mueller@informatik.uni-erlangen.de>
 * Copyright (C) 2012	Hans Spath <tresor@hans-spath.de>
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

#include <crypto/algapi.h>
#include <crypto/tresor.h>
#include <linux/module.h>
#include <crypto/aes.h>
#include <linux/smp.h>


/*
 * Assembly functions implemented in tresor-intel_asm.S
 */
asmlinkage bool tresor_capable(void);
asmlinkage void tresor_set_key(const u8 *in_key);
asmlinkage void tresor_encblk_128(u8 *out, const u8 *in);
asmlinkage void tresor_decblk_128(u8 *out, const u8 *in);
asmlinkage void tresor_encblk_192(u8 *out, const u8 *in);
asmlinkage void tresor_decblk_192(u8 *out, const u8 *in);
asmlinkage void tresor_encblk_256(u8 *out, const u8 *in);
asmlinkage void tresor_decblk_256(u8 *out, const u8 *in);



/*
 * Set-key pseudo function: Setting the real key for TRESOR must be done
 * separately. This is because of the kernel crypto API's key management,
 * which stores the key in RAM. We don't want to have the actual key in RAM, so
 * we give only a fake-key to the kernel key management.
 */
static int tresor_setdummykey(struct crypto_tfm *tfm, const u8 *in_key,
							unsigned int key_len)
{
	struct crypto_aes_ctx *ctx = crypto_tfm_ctx(tfm);

	switch (key_len) {
	case AES_KEYSIZE_128:
	case AES_KEYSIZE_192:
	case AES_KEYSIZE_256:
		ctx->key_length = key_len;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}


/*
 * Prolog: enter atomic section
 */
static inline void tresor_prolog(unsigned long *irq_flags)
{
	/* disable scheduler */
	preempt_disable();
	/* Calling local_irq_save saves and disables interrupts */
	local_irq_save(*irq_flags);
}


/*
 * Epilog: leave atomic section
 */
static inline void tresor_epilog(unsigned long *irq_flags)
{
	local_irq_restore(*irq_flags);
	preempt_enable();
}


/*
 * Encrypt one block
 */
void tresor_encrypt(struct crypto_tfm *tfm, u8 *dst, const u8 *src)
{
	struct crypto_aes_ctx *ctx = crypto_tfm_ctx(tfm);
	unsigned long irq_flags;

	tresor_prolog(&irq_flags);
	switch (ctx->key_length) {
	case AES_KEYSIZE_128:
		tresor_encblk_128(dst, src);
		break;
	case AES_KEYSIZE_192:
		tresor_encblk_192(dst, src);
		break;
	case AES_KEYSIZE_256:
		tresor_encblk_256(dst, src);
		break;
	}
	tresor_epilog(&irq_flags);
}


/*
 * Decrypt one block
 */
void tresor_decrypt(struct crypto_tfm *tfm, u8 *dst, const u8 *src)
{
	struct crypto_aes_ctx *ctx = crypto_tfm_ctx(tfm);
	unsigned long irq_flags;

	tresor_prolog(&irq_flags);
	switch (ctx->key_length) {
	case AES_KEYSIZE_128:
		tresor_decblk_128(dst, src);
		break;
	case AES_KEYSIZE_192:
		tresor_decblk_192(dst, src);
		break;
	case AES_KEYSIZE_256:
		tresor_decblk_256(dst, src);
		break;
	}
	tresor_epilog(&irq_flags);
}


/*
 * Set AES key (the real function this time, not dummy as above)
 */
static void tresor_setkey_current_cpu(void *data)
{
	printk(KERN_DEBUG "TRESOR: %s running on cpu %d\n",
		__func__, smp_processor_id());
	tresor_set_key((const u8 *)data);
}

void tresor_setkey(const u8 *in_key)
{
	on_each_cpu(tresor_setkey_current_cpu, (void *)in_key, 1);
}


/*
 * Crypto API algorithm
 */
static struct crypto_alg tresor_alg = {
	.cra_name		= "tresor",
	.cra_driver_name	= "tresor-driver",
	.cra_priority		= 100,
	.cra_flags		= CRYPTO_ALG_TYPE_CIPHER,
	.cra_blocksize		= AES_BLOCK_SIZE,
	.cra_ctxsize		= sizeof(struct crypto_aes_ctx),
	.cra_alignmask		= 3,
	.cra_module		= THIS_MODULE,
	.cra_list		= LIST_HEAD_INIT(tresor_alg.cra_list),
	.cra_u	= {
		.cipher	= {
			.cia_min_keysize	= AES_MIN_KEY_SIZE,
			.cia_max_keysize	= AES_MAX_KEY_SIZE,
			.cia_setkey		= tresor_setdummykey,
			.cia_encrypt		= tresor_encrypt,
			.cia_decrypt		= tresor_decrypt
		}
	}
};


/* Initialize module */
static int __init tresor_init(void)
{
	int retval;
	retval = crypto_register_alg(&tresor_alg);
	return retval;
}
module_init(tresor_init);


/* Remove module */
static void __exit tresor_fini(void)
{
	crypto_unregister_alg(&tresor_alg);
}
module_exit(tresor_fini);


/* Support TRESOR testing module  */
EXPORT_SYMBOL(tresor_setkey);
