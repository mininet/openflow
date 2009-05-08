/* Copyright (c) 2008 The Board of Trustees of The Leland Stanford
 * Junior University
 *
 * We are making the OpenFlow specification and associated documentation
 * (Software) available for public use and benefit with the expectation
 * that others will use, modify and enhance the Software and contribute
 * those enhancements back to the community. However, since we would
 * like to make the Software available for broadest use, with as few
 * restrictions as possible permission is hereby granted, free of
 * charge, to any person obtaining a copy of this Software to deal in
 * the Software under the copyrights without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * The name and trademarks of copyright holder(s) may NOT be used in
 * advertising or publicity pertaining to the Software or any
 * derivatives without specific, written prior permission.
 */

#include <config.h>
#include "vconn.h"
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "util.h"
#include "vconn-provider.h"
#include "vconn-stream.h"

#include "vlog.h"
#define THIS_MODULE VLM_vconn_fd

/* File descriptor. */

static int
fd_open(const char *name, char *suffix, struct vconn **vconnp)
{
    int fd = atoi(suffix);
    struct stat s;

    /* Check that 'fd' is really open and is really the right type of fd. */
    if (fstat(fd, &s) < 0) {
        VLOG_ERR("%s: failed to stat file descriptor %d: %s",
                 name, fd, strerror(errno));
        return errno;
    }
    if (!S_ISSOCK(s.st_mode)) {
        VLOG_ERR("%s: file descriptor %d is not a socket", name, fd);
        return errno;
    }

    return new_stream_vconn(name, fd, 0, 0, false, vconnp);
}

struct vconn_class fd_vconn_class = {
    "fd",                       /* name */
    fd_open,                    /* open */
    NULL,                       /* close */
    NULL,                       /* connect */
    NULL,                       /* recv */
    NULL,                       /* send */
    NULL,                       /* wait */
};
