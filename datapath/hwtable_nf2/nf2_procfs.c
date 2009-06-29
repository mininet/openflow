/*-
 * Copyright (c) 2008, 2009
 *      The Board of Trustees of The Leland Stanford Junior University
 *
 * We are making the OpenFlow specification and associated documentation
 * (Software) available for public use and benefit with the expectation that
 * others will use, modify and enhance the Software and contribute those
 * enhancements back to the community. However, since we would like to make the
 * Software available for broadest use, with as few restrictions as possible
 * permission is hereby granted, free of charge, to any person obtaining a copy
 * of this Software to deal in the Software under the copyrights without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * The name and trademarks of copyright holder(s) may NOT be used in
 * advertising or publicity pertaining to the Software or any derivatives
 * without specific, written prior permission.
 */

#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/rculist.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/delay.h>
#include <linux/if_arp.h>
#include <linux/proc_fs.h>

#include "chain.h"
#include "table.h"
#include "flow.h"
#include "datapath.h"

#include "hwtable_nf2/nf2_reg.h"
#include "hwtable_nf2/nf2_flowtable.h"
#include "hwtable_nf2/nf2_openflow.h"
#include "hwtable_nf2/nf2_lib.h"
#include "hwtable_nf2/nf2_procfs.h"

#define NF2_PROCFS_NAME "net/openflow-netfpga"
#define CLK_CYCLE 8

static struct semaphore proc_sem;

static int disp_dev_info(char *);
static int disp_port_info(char *);
static int disp_match_info(char *);
static int disp_watchdog_info(char *);
static int proc_read(char *, char **, off_t, int, int *, void *);

static int
disp_dev_info(char *page)
{
	struct net_device *netdev;
	struct nf2_device_info *nf2devinfo;
	int len = 0;

	netdev = nf2_get_net_device();
	if (netdev == NULL)
		return 0;
	nf2devinfo = nf2_get_device_info(netdev);
	if (nf2devinfo == NULL) {
		nf2_free_net_device(netdev);
		return 0;
	}
	nf2_free_net_device(netdev);

	len += sprintf(page + len,
		       "NetFPGA: "
		       "design name: %s, device ID: %d, device revision: %d\n",
		       nf2devinfo->nf2_device_str,
		       nf2devinfo->nf2_device_id, nf2devinfo->nf2_device_rev);
	len += sprintf(page + len, "\n");

	return len;
}

static int
disp_port_info(char *page)
{
	struct net_device *netdev;
	struct nf2_all_ports_info *nf2portinfo;
	int len = 0;
	int i;

	netdev = nf2_get_net_device();
	if (netdev == NULL)
		return 0;
	nf2portinfo = nf2_get_all_ports_info(netdev);
	if (nf2portinfo == NULL) {
		nf2_free_net_device(netdev);
		return 0;
	}
	nf2_free_net_device(netdev);

	for (i = 0; i < NF2_PORT_NUM; i++) {
		len += sprintf(page + len, "Interface nf2c%d\n", i);
		len += sprintf(page + len,
			       "  Input queue: %u/%u (current/queued)\n",
			       nf2portinfo->port[i].rx_q_num_pkts_in_queue,
			       nf2portinfo->port[i].rx_q_num_pkts_dequeued);
		len += sprintf(page + len,
			       "  %u packets input, %u dropped "
			       "(%u buffer exhausted, %u bad packets)\n"
			       "  %u pushed words, %u pushed bytes\n",
			       nf2portinfo->port[i].rx_q_num_pkts_stored,
			       nf2portinfo->port[i].rx_q_num_pkts_dropped_full
			       + nf2portinfo->port[i].rx_q_num_pkts_dropped_bad,
			       nf2portinfo->port[i].rx_q_num_pkts_dropped_full,
			       nf2portinfo->port[i].rx_q_num_pkts_dropped_bad,
			       nf2portinfo->port[i].rx_q_num_words_pushed,
			       nf2portinfo->port[i].rx_q_num_bytes_pushed);
		len += sprintf(page + len,
			       "  Output queue: %u/%u (current/queued)\n",
			       nf2portinfo->port[i].tx_q_num_pkts_in_queue,
			       nf2portinfo->port[i].tx_q_num_pkts_enqueued);
		len += sprintf(page + len,
			       "  %u packets output, "
			       "%u pushed words, %u pushed bytes\n",
			       nf2portinfo->port[i].tx_q_num_pkts_sent,
			       nf2portinfo->port[i].tx_q_num_words_pushed,
			       nf2portinfo->port[i].tx_q_num_bytes_pushed);
	}
	len += sprintf(page + len, "\n");

	return len;
}

static int
disp_match_info(char *page)
{
	struct net_device *netdev;
	struct nf2_match_info *nf2matchinfo;
	int len = 0;

	netdev = nf2_get_net_device();
	if (netdev == NULL)
		return 0;
	nf2matchinfo = nf2_get_match_info(netdev);
	if (nf2matchinfo == NULL) {
		nf2_free_net_device(netdev);
		return 0;
	}
	nf2_free_net_device(netdev);

	len += sprintf(page + len,
		       "WILDCARD match table lookup: %u/%u (hits/misses)\n",
		       nf2matchinfo->wildcard_hits,
		       nf2matchinfo->wildcard_misses);
	len += sprintf(page + len,
		       "EXACT match table lookup: %u/%u (hits/misses)\n",
		       nf2matchinfo->exact_hits, nf2matchinfo->exact_misses);
	len += sprintf(page + len, "\n");

	return len;
}

static int
disp_watchdog_info(char *page)
{
	struct net_device *netdev;
	unsigned int nf2wdtinfo;
	unsigned int elapsed_time;
	int len = 0;

#ifndef NF2_WATCHDOG
	return 0;
#endif

	netdev = nf2_get_net_device();
	if (netdev == NULL)
		return 0;
	nf2wdtinfo = nf2_get_watchdog_info(netdev);
	nf2_free_net_device(netdev);

	elapsed_time = nf2wdtinfo * CLK_CYCLE / 1000000;

	len += sprintf(page + len,
		       "%u (msec) passed since the watchdog counter has been cleared last time\n",
		       elapsed_time);
	len += sprintf(page + len, "\n");

	return len;
}

static int
proc_read(char *page, char **start, off_t offset, int count, int *eof,
	  void *data)
{
	int len = 0;
	int buf_pos = 1;

	if (down_interruptible(&proc_sem))
		return -ERESTARTSYS;

	if (buf_pos != 0) {
		len += disp_dev_info(page + len);
		len += disp_port_info(page + len);
		len += disp_match_info(page + len);
		len += disp_watchdog_info(page + len);
		buf_pos = 0;
	}
	up(&proc_sem);

	*eof = 1;
	return len;
}

void
nf2_create_procfs(void)
{
	struct proc_dir_entry *entry;

	entry = create_proc_entry(NF2_PROCFS_NAME,
				  S_IFREG | S_IRUGO | S_IWUGO, NULL);
	if (entry == NULL)
		return;

	entry->read_proc = proc_read;
	sema_init(&proc_sem, 1);
}

void
nf2_remove_procfs(void)
{
	remove_proc_entry(NF2_PROCFS_NAME, NULL);
}
