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

static void *tcpcrypt_init_resume_session(struct tcp_eno_syn_subopts *opts, bool role_B)
{
	return NULL;
}

static void *tcpcrypt_init_session(const u8 *remote_subopt_data, int remote_subopt_data_len, bool role_B)
{
	return NULL;
}

static bool tcpcrypt_tep_negotiated(void *session_data, const u8 *remote_subopt_data, int remote_subopt_data_len)
{
	return false;
}

static void tcpcrypt_free_session(void *session_data)
{
	if (session_data) {
		//TODO
	}
}

static struct tcp_eno_tep tep_p256 = {
	.init_resume_tep_session = tcpcrypt_init_resume_session,
	.init_tep_session        = tcpcrypt_init_session,
	.tep_negotiated          = tcpcrypt_tep_negotiated,
	.free_tep_session        = tcpcrypt_free_session,
	.tep_id                  = 0x21,
	.tep_module              = THIS_MODULE,
};

static int __init tcpcrypt_mod_init(void)
{
	int teps_registered = 0;

	/* TODO: This should get refs to crypto algapi before registering */

	if (tcp_eno_register_tep(&tep_p256)) {
		teps_registered++;
	}

	if (teps_registered == 0)
		return -ENOENT;
	return 0;
}

static void __exit tcpcrypt_mod_fini(void)
{
	return tcp_eno_unregister_tep(&tep_p256);
}

module_init(tcpcrypt_mod_init);
module_exit(tcpcrypt_mod_fini);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("tcpcrypt TCP ENO implementation");
