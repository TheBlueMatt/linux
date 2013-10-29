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
#include <linux/sched.h>


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
 * Define the wait structures for async (d)e(n)cryption
 */
static DEFINE_PER_CPU(bool, is_keyset);
static struct crypto_queue keywait_encrypt_queue;
static struct crypto_queue keywait_decrypt_queue;
static DEFINE_SPINLOCK(keywait_lock);

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

	BUG_ON(!get_cpu_var(is_keyset));
	put_cpu_var(is_keyset);

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
}


/*
 * Decrypt one block
 */
void tresor_decrypt(struct crypto_tfm *tfm, u8 *dst, const u8 *src)
{
	struct crypto_aes_ctx *ctx = crypto_tfm_ctx(tfm);

	BUG_ON(!get_cpu_var(is_keyset));
	put_cpu_var(is_keyset);

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
}


/*
 * Set AES key (the real function this time, not dummy as above)
 */
static int ablk_tresor_do_encrypt(struct ablkcipher_request *req, bool retVal);
static int ablk_tresor_do_decrypt(struct ablkcipher_request *req, bool retVal);

static void tresor_setkey_current_cpu(void *data)
{
	printk(KERN_DEBUG "TRESOR: %s running on cpu %d\n",
		__func__, smp_processor_id());
	tresor_set_key((const u8 *)data);

	get_cpu_var(is_keyset) = true;
	put_cpu_var(is_keyset);
}

void tresor_setkey(const u8 *in_key)
{
	struct crypto_async_request* backlog;
	struct ablkcipher_request* req;

	on_each_cpu(tresor_setkey_current_cpu, (void *)in_key, 1);

	spin_lock(&keywait_lock);
	backlog = crypto_get_backlog(&keywait_encrypt_queue);
	while ((req = ablkcipher_dequeue_request(&keywait_encrypt_queue)) != NULL)
		ablk_tresor_do_encrypt(req, false);
	if (backlog)
		backlog->complete(backlog, -EINPROGRESS);

	backlog = crypto_get_backlog(&keywait_decrypt_queue);
	while ((req = ablkcipher_dequeue_request(&keywait_decrypt_queue)) != NULL)
		ablk_tresor_do_decrypt(req, false);
	if (backlog)
		backlog->complete(backlog, -EINPROGRESS);

	spin_unlock(&keywait_lock);
}

static void tresor_notify_keyunset_current_cpu()
{
	get_cpu_var(is_keyset) = false;
	put_cpu_var(is_keyset);
}

void tresor_notify_keyunset(void)
{
	spin_lock(&keywait_lock);
	if (!keywait_encrypt_queue.max_qlen)
		crypto_init_queue(&keywait_encrypt_queue, 1024);
	if (!keywait_decrypt_queue.max_qlen)
		crypto_init_queue(&keywait_decrypt_queue, 1024);
	spin_unlock(&keywait_lock);
	on_each_cpu(tresor_notify_keyunset_current_cpu, NULL, 1);
}


/*
 * Functions to wrap tresor in an async cipher to wait for key to be set.
 */
static int ablk_tresor_do_encrypt(struct ablkcipher_request *req, bool retVal)
{
	struct crypto_ablkcipher *tfm = crypto_ablkcipher_reqtfm(req);
	struct crypto_blkcipher **ctx = crypto_ablkcipher_ctx(tfm);
	struct blkcipher_desc desc;
	unsigned long irq_flags;
	int ret;

	desc.tfm = *ctx;
	desc.info = req->info;
	desc.flags = 0;

	tresor_prolog(&irq_flags);
	if (*ctx)
		ret = crypto_blkcipher_encrypt_iv(&desc, req->dst, req->src, req->nbytes);
	else
		ret = -EINVAL;
	tresor_epilog(&irq_flags);

	if (!retVal && req->base.complete)
		req->base.complete(&req->base, ret);
	else if (retVal)
		return ret;

	return 0;
}

static int ablk_tresor_do_decrypt(struct ablkcipher_request *req, bool retVal)
{
	struct crypto_ablkcipher *tfm = crypto_ablkcipher_reqtfm(req);
	struct crypto_blkcipher **ctx = crypto_ablkcipher_ctx(tfm);
	struct blkcipher_desc desc;
	unsigned long irq_flags;
	int ret;

	desc.tfm = *ctx;
	desc.info = req->info;
	desc.flags = 0;

	tresor_prolog(&irq_flags);
	if (*ctx)
		ret = crypto_blkcipher_decrypt_iv(&desc, req->dst, req->src, req->nbytes);
	else
		ret = -EINVAL;
	tresor_epilog(&irq_flags);

	if (!retVal && req->base.complete)
		req->base.complete(&req->base, ret);
	else if (retVal)
		return ret;

	return 0;
}

int ablk_tresor_encrypt(struct ablkcipher_request *req)
{
	int ret;

	if (!get_cpu_var(is_keyset)) {
		spin_lock(&keywait_lock);
		ret = ablkcipher_enqueue_request(&keywait_encrypt_queue, req);
		spin_unlock(&keywait_lock);
	} else
		ret = ablk_tresor_do_encrypt(req, true);

	put_cpu_var(is_keyset);
	return ret;
}
int ablk_tresor_decrypt(struct ablkcipher_request *req)
{
	int ret;

	if (!get_cpu_var(is_keyset)) {
		spin_lock(&keywait_lock);
		ret = ablkcipher_enqueue_request(&keywait_decrypt_queue, req);
		spin_unlock(&keywait_lock);
	} else
		ret = ablk_tresor_do_decrypt(req, true);

	put_cpu_var(is_keyset);
	return ret;
}
int ablk_tresor_cbc_init(struct crypto_tfm *tfm)
{
	struct crypto_blkcipher **ctx = crypto_tfm_ctx(tfm);

	*ctx = crypto_alloc_blkcipher("cbc(__tresor)", 0, 0);
	if (IS_ERR(*ctx))
		return PTR_ERR(*ctx);

	return 0;
}
void ablk_tresor_exit(struct crypto_tfm *tfm)
{
	struct crypto_blkcipher **ctx = crypto_tfm_ctx(tfm);

	if (*ctx)
		crypto_free_blkcipher(*ctx);
	*ctx = NULL;
}
int ablk_tresor_setdummykey(struct crypto_ablkcipher *tfm, const u8 *key,
							unsigned int keylen)
{
	struct crypto_blkcipher **ctx = crypto_ablkcipher_ctx(tfm);

	if (*ctx)
		return crypto_blkcipher_setkey(*ctx, key, keylen);
	else
		return -EINVAL;
}


/*
 * Crypto API algorithm
 */
static struct crypto_alg tresor_algs[] = {
{
	.cra_name		= "__tresor",
	.cra_driver_name	= "__tresor-driver",
	.cra_priority		= 100,
	.cra_flags		= CRYPTO_ALG_TYPE_CIPHER,
	.cra_blocksize		= AES_BLOCK_SIZE,
	.cra_ctxsize		= sizeof(struct crypto_aes_ctx),
	.cra_alignmask		= 3,
	.cra_module		= THIS_MODULE,
	.cra_u	= {
		.cipher	= {
			.cia_min_keysize	= AES_MIN_KEY_SIZE,
			.cia_max_keysize	= AES_MAX_KEY_SIZE,
			.cia_setkey		= tresor_setdummykey,
			.cia_encrypt		= tresor_encrypt,
			.cia_decrypt		= tresor_decrypt
		}
	}
},
{
	.cra_name		= "cbc(tresor)",
	.cra_driver_name	= "tresor-cbc-driver",
	.cra_priority		= 500,
	.cra_flags		= CRYPTO_ALG_TYPE_ABLKCIPHER | CRYPTO_ALG_ASYNC,
	.cra_blocksize		= AES_BLOCK_SIZE,
	.cra_ctxsize		= sizeof(struct crypto_blkcipher **),
	.cra_alignmask		= 3,
	.cra_type		= &crypto_ablkcipher_type,
	.cra_module		= THIS_MODULE,
	.cra_init		= ablk_tresor_cbc_init,
	.cra_exit		= ablk_tresor_exit,
	.cra_u = {
		.ablkcipher = {
			.min_keysize	= AES_MIN_KEY_SIZE,
			.max_keysize	= AES_MAX_KEY_SIZE,
			.ivsize		= AES_BLOCK_SIZE,
			.setkey		= ablk_tresor_setdummykey,
			.encrypt	= ablk_tresor_encrypt,
			.decrypt	= ablk_tresor_decrypt,
		},
	}
}};


/* Initialize module */
static int __init tresor_init(void)
{
	return crypto_register_algs(tresor_algs, ARRAY_SIZE(tresor_algs));
}
module_init(tresor_init);


/* Remove module */
static void __exit tresor_fini(void)
{
	crypto_unregister_algs(tresor_algs, ARRAY_SIZE(tresor_algs));
}
module_exit(tresor_fini);


/* Support TRESOR testing module  */
EXPORT_SYMBOL(tresor_setkey);
