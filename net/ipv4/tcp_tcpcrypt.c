/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system. INET is implemented using the BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		TCP-TCPCRYPT Implementation
 *
 * Author:	Matt Corallo <linux@bluematt.me>
 *
   This program is free software; you can redistribute it and/or modify it under
   the terms of the GNU General Public License as published by the Free Software
   Foundation; either version 2 of the License, or (at your option) any later
   version.
*/

#include <net/tcp_eno.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <crypto/kpp.h>
#include <crypto/aead.h>

#define CONST_NEXTK       0x01
#define CONST_SESSID      0x02
#define CONST_REKEY       0x03
#define CONST_KEY_A       0x04
#define CONST_KEY_B       0x05
#define CONST_RESUME      0x05
#define INIT1_MAGIC       0x15101a0e
#define INIT2_MAGIC       0x097105e0
#define FRAME_NONCE_MAGIC 0x44415441

#define TCPCRYPT_AEAD_AES_128_GCM       0x01
#define TCPCRYPT_AEAD_AES_256_GCM       0x02
#define TCPCRYPT_AEAD_CHACHA20_POLY1305 0x10

/* TODO: Need to do some locking on worker lists */
static LIST_HEAD(tcpcrypt_aes_aead_workers);
static LIST_HEAD(tcpcrypt_aes_aead_available_workers);

static LIST_HEAD(tcpcrypt_ecdh_kpp_workers);
static LIST_HEAD(tcpcrypt_ecdh_kpp_available_workers);

struct tcpcrypt_aead_worker {
	struct crypto_aead *aead_tfm;
	struct list_head worker_list;
	struct list_head avail_worker_list;
};

struct tcpcrypt_kpp_worker {
	struct crypto_kpp *kpp_tfm;
	struct list_head worker_list;
	struct list_head avail_worker_list;
};

/* TODO: Check alloc types EVERYWHERE in here! */

static bool create_aes_aead_worker(void)
{
	struct tcpcrypt_aead_worker *worker = kzalloc(sizeof(struct tcpcrypt_aead_worker), GFP_KERNEL);
	worker->aead_tfm = crypto_alloc_aead("aes", 0, 0);
	if (IS_ERR(worker->aead_tfm))
		goto err;

	list_add(&worker->worker_list, &tcpcrypt_aes_aead_workers);
	list_add(&worker->avail_worker_list, &tcpcrypt_aes_aead_available_workers);
	return true;

err:
	kfree(worker);
	return false;
}

static bool create_ecdh_kpp_worker(void)
{
	struct tcpcrypt_kpp_worker *worker = kzalloc(sizeof(struct tcpcrypt_kpp_worker), GFP_KERNEL);
	worker->kpp_tfm = crypto_alloc_kpp("ecdh", 0, 0);
	if (IS_ERR(worker->kpp_tfm))
		goto err;

	list_add(&worker->worker_list, &tcpcrypt_ecdh_kpp_workers);
	list_add(&worker->avail_worker_list, &tcpcrypt_ecdh_kpp_available_workers);
	return true;

err:
	kfree(worker);
	return false;
}

static struct tcpcrypt_aead_worker *get_aes_aead_worker(void)
{
	struct tcpcrypt_aead_worker *res;

	if (list_empty(&tcpcrypt_aes_aead_available_workers))
		if (!create_aes_aead_worker())
			return NULL;

	res = list_first_entry(&tcpcrypt_aes_aead_available_workers, struct tcpcrypt_aead_worker, avail_worker_list);
	list_del(&res->avail_worker_list);

	return res;
}

static void put_aes_aead_worker(struct tcpcrypt_aead_worker *worker)
{
	list_add(&worker->avail_worker_list, &tcpcrypt_aes_aead_available_workers);
	/* TODO: Free the worker if we have too many (but NEVER drop to 0) */
}

static struct tcpcrypt_kpp_worker *get_ecdh_kpp_worker(void)
{
	struct tcpcrypt_kpp_worker *res;

	if (list_empty(&tcpcrypt_ecdh_kpp_available_workers))
		if (!create_ecdh_kpp_worker())
			return NULL;

	res = list_first_entry(&tcpcrypt_ecdh_kpp_available_workers, struct tcpcrypt_kpp_worker, avail_worker_list);
	list_del(&res->avail_worker_list);

	return res;
}

static void put_ecdh_kpp_worker(struct tcpcrypt_kpp_worker *worker)
{
	list_add(&worker->avail_worker_list, &tcpcrypt_ecdh_kpp_available_workers);
	/* TODO: Free the worker if we have too many (but NEVER drop to 0) */
}


struct tcpcrypt_session_data {
	bool role_B : 1;
	struct tcpcrypt_aead_worker *aes_worker;
	struct tcpcrypt_kpp_worker  *ecdh_worker;
};

static void tcpcrypt_free_session(void *_session_data)
{
	struct tcpcrypt_session_data *session_data = (struct tcpcrypt_session_data *)_session_data;
	if (session_data) {
		if (session_data->aes_worker)
			put_aes_aead_worker(session_data->aes_worker);
		if (session_data->ecdh_worker)
			put_ecdh_kpp_worker(session_data->ecdh_worker);
		kfree(session_data);
	}
}

static void *tcpcrypt_init_resume_session(struct tcp_eno_syn_subopts *opts, bool role_B)
{
	/* TODO: We do not (yet) support sesssion resumption */
	return NULL;
}

static void *tcpcrypt_init_session(const u8 *remote_subopt_data, int remote_subopt_data_len, bool role_B)
{
	struct tcpcrypt_session_data *session_data = kzalloc(sizeof(struct tcpcrypt_session_data), GFP_KERNEL);
	if (!session_data) goto err;

	session_data->role_B = role_B;

	if (remote_subopt_data_len && remote_subopt_data) {
		/* TODO: We do not (yet) support sesssion resumption */
	}

	return session_data;

err:
	tcpcrypt_free_session(session_data);
	return NULL;
}

static bool tcpcrypt_tep_negotiated(void *_session_data, const u8 *remote_subopt_data, int remote_subopt_data_len)
{
	struct tcpcrypt_session_data *session_data = (struct tcpcrypt_session_data *)_session_data;
	BUG_ON(!session_data);

	if (!session_data->ecdh_worker)
		session_data->ecdh_worker = get_ecdh_kpp_worker();
	if (!session_data->ecdh_worker)
		return false;

	if (!session_data->role_B) {
		/* TODO: Generate handshake */
	}

	return true;
}

static void tcpcrypt_receive_data(void *_session_data, const u8 *remote_subopt_data, int remote_subopt_data_len) {
	struct tcpcrypt_session_data *session_data = (struct tcpcrypt_session_data *)_session_data;
	BUG_ON(!session_data);

	if (!session_data->aes_worker)
		session_data->aes_worker = get_aes_aead_worker();
	if (!session_data->aes_worker)
		return;
}

static void free_workers(void)
{
	struct tcpcrypt_aead_worker *aead_worker;
	struct tcpcrypt_kpp_worker  *kpp_worker;

	list_for_each_entry(aead_worker, &tcpcrypt_aes_aead_available_workers, worker_list) {
		crypto_free_aead(aead_worker->aead_tfm);
		list_del(&aead_worker->worker_list);
	}
	INIT_LIST_HEAD(&tcpcrypt_aes_aead_available_workers);
	BUG_ON(!list_empty(&tcpcrypt_aes_aead_workers)); /* All workers must have been available */

	list_for_each_entry(kpp_worker, &tcpcrypt_ecdh_kpp_available_workers, worker_list) {
		crypto_free_kpp(kpp_worker->kpp_tfm);
		list_del(&kpp_worker->worker_list);
	}
	INIT_LIST_HEAD(&tcpcrypt_ecdh_kpp_available_workers);
	BUG_ON(!list_empty(&tcpcrypt_ecdh_kpp_workers)); /* All workers must have been available */
}

static struct tcp_eno_tep tep_p256 = {
	.init_resume_tep_session = tcpcrypt_init_resume_session,
	.init_tep_session        = tcpcrypt_init_session,
	.tep_negotiated          = tcpcrypt_tep_negotiated,
	.receive_data            = tcpcrypt_receive_data,
	.free_tep_session        = tcpcrypt_free_session,
	.tep_id                  = 0x21,
	.tep_module              = THIS_MODULE,
};

static int __init tcpcrypt_mod_init(void)
{
	int teps_registered = 0;

	if (!create_aes_aead_worker())
		goto err;

	if (!create_ecdh_kpp_worker())
		goto err;

	if (tcp_eno_register_tep(&tep_p256))
		teps_registered++;

	if (teps_registered == 0)
		goto err;
	return 0;
err:
	free_workers();

	return -ENOENT;
}

static void __exit tcpcrypt_mod_fini(void)
{
	tcp_eno_unregister_tep(&tep_p256);
	free_workers();
}

module_init(tcpcrypt_mod_init);
module_exit(tcpcrypt_mod_fini);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("tcpcrypt TCP ENO implementation");
