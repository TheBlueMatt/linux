#include <linux/async.h>
#include <linux/delay.h>
#include <linux/kernel.h>
#include <crypto/tresor.h>

#include "do_mounts.h"

// TRESOR device for single keydevice
static char saved_tresor_name[64];
static int __init tresor_dev_setup(char *line)
{
	strlcpy(saved_tresor_name, line, sizeof(saved_tresor_name));
	return 1;
}
__setup("tresorkeydevice=", tresor_dev_setup);


// TRESOR devices for multiple keydevices (combined with Shamir's secret sharing)
// Update TRESOR_MAX_KEY_DEVICES in tresor.h if the count is changed
static char saved_tresor_name_0[64];
static int __init tresor_dev_setup_0(char *line)
{
	strlcpy(saved_tresor_name_0, line, sizeof(saved_tresor_name_0));
	return 1;
}
__setup("tresorsharedevice0=", tresor_dev_setup_0);

static char saved_tresor_name_1[64];
static int __init tresor_dev_setup_1(char *line)
{
	strlcpy(saved_tresor_name_1, line, sizeof(saved_tresor_name_1));
	return 1;
}
__setup("tresorsharedevice1=", tresor_dev_setup_1);

static char saved_tresor_name_2[64];
static int __init tresor_dev_setup_2(char *line)
{
	strlcpy(saved_tresor_name_2, line, sizeof(saved_tresor_name_2));
	return 1;
}
__setup("tresorsharedevice2=", tresor_dev_setup_2);

static char saved_tresor_name_3[64];
static int __init tresor_dev_setup_3(char *line)
{
	strlcpy(saved_tresor_name_3, line, sizeof(saved_tresor_name_3));
	return 1;
}
__setup("tresorsharedevice3=", tresor_dev_setup_3);

static char saved_tresor_name_4[64];
static int __init tresor_dev_setup_4(char *line)
{
	strlcpy(saved_tresor_name_4, line, sizeof(saved_tresor_name_4));
	return 1;
}
__setup("tresorsharedevice4=", tresor_dev_setup_4);

static char saved_tresor_name_5[64];
static int __init tresor_dev_setup_5(char *line)
{
	strlcpy(saved_tresor_name_5, line, sizeof(saved_tresor_name_5));
	return 1;
}
__setup("tresorsharedevice5=", tresor_dev_setup_5);

static char saved_tresor_name_6[64];
static int __init tresor_dev_setup_6(char *line)
{
	strlcpy(saved_tresor_name_6, line, sizeof(saved_tresor_name_6));
	return 1;
}
__setup("tresorsharedevice6=", tresor_dev_setup_6);

static char saved_tresor_name_7[64];
static int __init tresor_dev_setup_7(char *line)
{
	strlcpy(saved_tresor_name_7, line, sizeof(saved_tresor_name_7));
	return 1;
}
__setup("tresorsharedevice7=", tresor_dev_setup_7);

static char saved_tresor_name_8[64];
static int __init tresor_dev_setup_8(char *line)
{
	strlcpy(saved_tresor_name_8, line, sizeof(saved_tresor_name_8));
	return 1;
}
__setup("tresorsharedevice8=", tresor_dev_setup_8);

static char saved_tresor_name_9[64];
static int __init tresor_dev_setup_9(char *line)
{
	strlcpy(saved_tresor_name_9, line, sizeof(saved_tresor_name_9));
	return 1;
}
__setup("tresorsharedevice9=", tresor_dev_setup_9);

int tresor_shares_required = 0;
static int __init tresor_shares_required_setup(char *line)
{
	if (kstrtoint(line, 10, &tresor_shares_required) || tresor_shares_required < 1 || tresor_shares_required > 10)
	{
		printk(KERN_ERR "tresorsharesrequired out of range [1, 10]\n");
		tresor_shares_required = 0;
	}
	return 1;
}
__setup("tresorsharesrequired=", tresor_shares_required_setup);


// Optional compat mode for TRESOR shamir's mode
unsigned char tresor_shamirs_compat = 0;
static int __init tresor_shamirs_compat_setup(char *line)
{
	tresor_shamirs_compat = 1;
	return 1;
}
__setup("tresorshamirscompat", tresor_shamirs_compat_setup);


static struct tresor_device_and_name tresor_next_dev_wait_intern(char* tresor_device_name[], char tresor_devices_used[]) {
	int i;
	dev_t TRESOR_DEV = 0;

	struct tresor_device_and_name res;
	res.dev = NULL;

	for (i = 0; i < TRESOR_MAX_KEY_DEVICES; i++)
	{
		if (tresor_device_name[i] && !tresor_devices_used[i]) {
			TRESOR_DEV = name_to_dev_t(tresor_device_name[i]);
			if (TRESOR_DEV)
			{
				res.dev = blkdev_get_by_dev(TRESOR_DEV, FMODE_READ, NULL);
				if (!IS_ERR(res.dev)) {
					tresor_devices_used[i] = 1;
					res.name = tresor_device_name[i];
					return res;
				}
				TRESOR_DEV = 0;
			}
		}
	}
	res.dev = NULL; res.name = NULL;
	return res;
}

/* Much of this copied from prepare_namespace(void) */
struct tresor_device_and_name tresor_next_dev_wait(char tresor_devices_used[])
{
	char* tresor_device_name[TRESOR_MAX_KEY_DEVICES];
	struct tresor_device_and_name res;
	res.dev = NULL; res.name = NULL;

	memset(tresor_device_name, 0, sizeof(tresor_device_name));

	if (saved_tresor_name[0] || tresor_shares_required)
	{
		/*
		 * wait for the known devices to complete their probing
		 *
		 * Note: this is a potential source of long boot delays.
		 * For example, it is not atypical to wait 5 seconds here
		 * for the touchpad of a laptop to initialize.
		 */
		wait_for_device_probe();

		md_run_setup();

		if (tresor_shares_required)
		{
			tresor_device_name[0] = saved_tresor_name_0;
			tresor_device_name[1] = saved_tresor_name_1;
			tresor_device_name[2] = saved_tresor_name_2;
			tresor_device_name[3] = saved_tresor_name_3;
			tresor_device_name[4] = saved_tresor_name_4;
			tresor_device_name[5] = saved_tresor_name_5;
			tresor_device_name[6] = saved_tresor_name_6;
			tresor_device_name[7] = saved_tresor_name_7;
			tresor_device_name[8] = saved_tresor_name_8;
			tresor_device_name[9] = saved_tresor_name_9;
		}
		else
		{
			tresor_device_name[0] = saved_tresor_name;
		}

		res = tresor_next_dev_wait_intern(tresor_device_name, tresor_devices_used);
		if (res.dev)
			return res;

		/* wait for any asynchronous scanning to complete */
		printk(KERN_INFO "Waiting for tresor device(s)...\n");
		while (driver_probe_done() != 0) {
			res = tresor_next_dev_wait_intern(tresor_device_name, tresor_devices_used);
			if (res.dev)
				return res;

			msleep(100);
		}
		async_synchronize_full();

		/* Now we just wait... */
		while (!res.dev) {
			msleep(100);
			res = tresor_next_dev_wait_intern(tresor_device_name, tresor_devices_used);
		}
	}

	return res;
}
