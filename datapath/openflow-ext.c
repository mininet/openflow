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

#include "openflow/openflow-ext.h"

#include "chain.h"
#include "datapath.h"
#include "table.h"
#include "private-msg.h"

/***
 * Copy the new dp_desc out of the passed message
 */

int
recv_of_set_dp_desc(struct datapath *dp, const struct sender * sender,
    const struct openflow_extension_header  *ofexth)
{
    struct openflow_ext_set_dp_desc * set_dp_desc = (struct openflow_ext_set_dp_desc * )
                ofexth;
    memcpy(dp->dp_desc, set_dp_desc->dp_desc, DESC_STR_LEN);
    dp->dp_desc[DESC_STR_LEN-1] = 0;        // force null for safety
    return 0;
}


int
openflow_ext_recv_msg(struct sw_chain *chain, const struct sender *sender,
		 const void *ofph)
{
	int error = 0;
    const struct openflow_queue_command_header  *ofexth = ofph;

    switch (ntohl(ofexth->header.subtype)) {
        /**** added here as a place holder
         * case OFP_EXT_QUEUE_MODIFY: {
         *                              recv_of_exp_queue_modify(dp,sender,oh);
         *                             return 0;
         *                         }
         * case OFP_EXT_QUEUE_DELETE: {
         *                             recv_of_exp_queue_delete(dp,sender,oh);
         *                             return 0;
         *                         }
         */
        case OFP_EXT_SET_DESC:
            return recv_of_set_dp_desc(chain->dp,sender,ofexth);
        default:
           VLOG_ERR("Received unknown command of type %d",
                   ntohl(ofexth->header.subtype));
           return -EINVAL;
    }

	return error;
}
