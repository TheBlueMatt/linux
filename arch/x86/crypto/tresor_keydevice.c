#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/completion.h>

#include <crypto/tresor.h>

#if PAGE_SIZE < 512 + TRESOR_MAX_PASSWORD_LENGTH
#error "TRESOR with keydevices doesn't support PAGE_SIZEs smaller than 512 + password length bytes"
// We already require AES-NI...why not this too?
#endif

struct bio_batch {
	int			err;
	struct completion	*wait;
};

static void tresor_read_keydevice_end(struct bio *bio, int err)
{
	struct bio_batch *bb = bio->bi_private;

	bb->err = err;
	complete(bb->wait);
	bio_put(bio);
}

int tresor_read_keydevice_sector(struct block_device *bdev, sector_t sector,
			    struct page *page)
{
	DECLARE_COMPLETION_ONSTACK(wait);
	struct bio_batch bb;
	struct bio *bio;

	bb.err = 0;
	bb.wait = &wait;

	bio = bio_alloc(GFP_KERNEL, 1);
	if (unlikely(!bio))
		return -ENOMEM;

	bio->bi_iter.bi_sector = sector;
	bio->bi_bdev = bdev;
	bio->bi_rw = READ;
	bio->bi_end_io = tresor_read_keydevice_end;
	bio->bi_private = &bb;

	bio->bi_iter.bi_size = bdev_logical_block_size(bdev);
	if (bio->bi_iter.bi_size > PAGE_SIZE)
		bio->bi_iter.bi_size = PAGE_SIZE;

	bio->bi_vcnt = 1;
	bio->bi_io_vec[0].bv_page = page;
	bio->bi_io_vec[0].bv_offset = 0;
	bio->bi_io_vec[0].bv_len = bio->bi_iter.bi_size;

	generic_make_request(bio);

	/* Wait for bios in-flight */
	wait_for_completion(&wait);

	return bb.err;
}
