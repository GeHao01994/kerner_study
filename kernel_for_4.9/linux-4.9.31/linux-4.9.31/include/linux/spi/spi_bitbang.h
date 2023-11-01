#ifndef	__SPI_BITBANG_H
#define	__SPI_BITBANG_H

#include <linux/workqueue.h>

struct spi_bitbang {
	struct mutex		lock;
	//busy置1的时候表示传输事务正在进行
	u8			busy;
	u8			use_dma;
	u8			flags;		/* extra spi->mode support */
	//关联的SPI控制器
	struct spi_master	*master;

	/* setup_transfer() changes clock and/or wordsize to match settings
	 * for this transfer; zeroes restore defaults from spi_device.
	 */
	 //为特定的传输设置时钟、字宽等属性的方法
	int	(*setup_transfer)(struct spi_device *spi,
			struct spi_transfer *t);
	//设备片选的方法
	void	(*chipselect)(struct spi_device *spi, int is_on);
#define	BITBANG_CS_ACTIVE	1	/* normally nCS, active low */
#define	BITBANG_CS_INACTIVE	0

	/* txrx_bufs() may handle dma mapping for transfers that don't
	 * already have one (transfer.{tx,rx}_dma is zero), or use PIO
	 */
	 //实际的传输方法
	int	(*txrx_bufs)(struct spi_device *spi, struct spi_transfer *t);
	//按自己传输的方法，如果控制器具备这样的功能则可以不实现
	/* txrx_word[SPI_MODE_*]() just looks like a shift register */
	u32	(*txrx_word[4])(struct spi_device *spi,
			unsigned nsecs,
			u32 word, u8 bits);
};

/* you can call these default bitbang->master methods from your custom
 * methods, if you like.
 */
extern int spi_bitbang_setup(struct spi_device *spi);
extern void spi_bitbang_cleanup(struct spi_device *spi);
extern int spi_bitbang_setup_transfer(struct spi_device *spi,
				      struct spi_transfer *t);

/* start or stop queue processing */
extern int spi_bitbang_start(struct spi_bitbang *spi);
extern void spi_bitbang_stop(struct spi_bitbang *spi);

#endif	/* __SPI_BITBANG_H */
