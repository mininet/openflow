/*-
 * Copyright (c) 2008, 2009, 2010
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

#ifndef HWTABLE_NF2_NF2_LIB_H_
#define HWTABLE_NF2_NF2_LIB_H_

struct nf2device *nf2_get_net_device(void);
void nf2_free_net_device(struct nf2device *);
int nf2_are_actions_supported(struct sw_flow *);
void nf2_clear_of_exact(uint32_t);
void nf2_clear_of_wildcard(uint32_t);
int nf2_init_exact_freelist(void);
int nf2_init_wildcard_freelist(void);
void nf2_destroy_exact_freelist(void);
void nf2_destroy_wildcard_freelist(void);
int nf2_write_static_wildcard(void);
void nf2_populate_of_entry(nf2_of_entry_wrap *, struct sw_flow *);
void nf2_populate_of_mask(nf2_of_mask_wrap *, struct sw_flow *);
void nf2_populate_of_action(nf2_of_action_wrap *, nf2_of_entry_wrap *,
			    struct sw_flow *);
void nf2_add_free_exact(struct nf2_flow *);
void nf2_add_free_wildcard(struct nf2_flow *);
int nf2_get_table_type(struct sw_flow *);
int nf2_build_and_write_flow(struct sw_flow *);
void nf2_delete_private(void *);
int nf2_modify_acts(struct sw_flow *);
uint64_t nf2_get_packet_count(struct nf2device *, struct nf2_flow *);
uint64_t nf2_get_byte_count(struct nf2device *, struct nf2_flow *);

#endif
