#include <linux/async.h>
#include <linux/delay.h>
#include <crypto/tresor.h>

#include "do_mounts.h"

static char saved_tresor_name[64];
static int __init tresor_dev_setup(char *line)
{
	strlcpy(saved_tresor_name, line, sizeof(saved_tresor_name));
	return 1;
}

__setup("tresorkeydevice=", tresor_dev_setup);

/* Esentially just a copy of prepare_namespace(void) */
struct block_device* tresor_dev_wait(void)
{
	char* tresor_device_name;
	dev_t TRESOR_DEV = 0;
	struct block_device* tresor_device;

	if (saved_tresor_name[0])
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

		tresor_device_name = saved_tresor_name;
		TRESOR_DEV = name_to_dev_t(tresor_device_name);

		/* wait for any asynchronous scanning to complete */
		if (TRESOR_DEV == 0) {
			printk(KERN_INFO "Waiting for tresor device %s...\n",
				saved_tresor_name);
			while (driver_probe_done() != 0 ||
				(TRESOR_DEV = name_to_dev_t(saved_tresor_name)) == 0)
				msleep(100);
			async_synchronize_full();
		}

		if (TRESOR_DEV == 0)
			TRESOR_DEV = name_to_dev_t(saved_tresor_name);
	}

	if (TRESOR_DEV != 0) {
		tresor_device = blkdev_get_by_dev(TRESOR_DEV, FMODE_READ, NULL);
		if (IS_ERR(tresor_device))
			return NULL;
		else
			return tresor_device;
	} else
		return NULL;
}
