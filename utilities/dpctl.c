/* Copyright (c) 2008, 2009 The Board of Trustees of The Leland Stanford
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
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>

#ifdef HAVE_NETLINK
#include "netdev.h"
#include "netlink.h"
#include "openflow/openflow-netlink.h"
#endif

#include "command-line.h"
#include "compiler.h"
#include "dpif.h"
#include "openflow/nicira-ext.h"
#include "ofp-print.h"
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "packets.h"
#include "random.h"
#include "socket-util.h"
#include "timeval.h"
#include "util.h"
#include "vconn-ssl.h"
#include "vconn.h"

#include "xtoxll.h"
#include "ofpstat.h"
#include "openflow/private-ext.h"

#include "vlog.h"
#define THIS_MODULE VLM_dpctl

#define DEFAULT_IDLE_TIMEOUT 60

/* Maximum size of action buffer for adding and modify flows */
#define MAX_ACT_LEN 60

#define MOD_PORT_CMD_UP      "up"
#define MOD_PORT_CMD_DOWN    "down"
#define MOD_PORT_CMD_FLOOD   "flood"
#define MOD_PORT_CMD_NOFLOOD "noflood"


/* Settings that may be configured by the user. */
struct settings {
    bool strict;        /* Use strict matching for flow mod commands */
};

struct command {
    const char *name;
    int min_args;
    int max_args;
    void (*handler)(const struct settings *, int argc, char *argv[]);
};

static struct command all_commands[];

static void usage(void) NO_RETURN;
static void parse_options(int argc, char *argv[], struct settings *);

int main(int argc, char *argv[])
{
    struct settings s;
    struct command *p;

    set_program_name(argv[0]);
    time_init();
    vlog_init();
    parse_options(argc, argv, &s);
    signal(SIGPIPE, SIG_IGN);

    argc -= optind;
    argv += optind;
    if (argc < 1)
        ofp_fatal(0, "missing command name; use --help for help");

    for (p = all_commands; p->name != NULL; p++) {
        if (!strcmp(p->name, argv[0])) {
            int n_arg = argc - 1;
            if (n_arg < p->min_args)
                ofp_fatal(0, "'%s' command requires at least %d arguments",
                          p->name, p->min_args);
            else if (n_arg > p->max_args)
                ofp_fatal(0, "'%s' command takes at most %d arguments",
                          p->name, p->max_args);
            else {
                p->handler(&s, argc, argv);
                if (ferror(stdout)) {
                    ofp_fatal(0, "write to stdout failed");
                }
                if (ferror(stderr)) {
                    ofp_fatal(0, "write to stderr failed");
                }
                exit(0);
            }
        }
    }
    ofp_fatal(0, "unknown command '%s'; use --help for help", argv[0]);

    return 0;
}

static void
parse_options(int argc, char *argv[], struct settings *s)
{
    enum {
        OPT_STRICT = UCHAR_MAX + 1
    };
    static struct option long_options[] = {
        {"timeout", required_argument, 0, 't'},
        {"verbose", optional_argument, 0, 'v'},
        {"strict", no_argument, 0, OPT_STRICT},
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'V'},
        VCONN_SSL_LONG_OPTIONS
        {0, 0, 0, 0},
    };
    char *short_options = long_options_to_short_options(long_options);

    /* Set defaults that we can figure out before parsing options. */
    s->strict = false;

    for (;;) {
        unsigned long int timeout;
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 't':
            timeout = strtoul(optarg, NULL, 10);
            if (timeout <= 0) {
                ofp_fatal(0, "value %s on -t or --timeout is not at least 1",
                          optarg);
            } else {
                time_alarm(timeout);
            }
            break;

        case 'h':
            usage();

        case 'V':
            printf("%s %s compiled "__DATE__" "__TIME__"\n",
                   program_name, VERSION BUILDNR);
            exit(EXIT_SUCCESS);

        case 'v':
            vlog_set_verbosity(optarg);
            break;

        case OPT_STRICT:
            s->strict = true;
            break;

        VCONN_SSL_OPTION_HANDLERS

        case '?':
            exit(EXIT_FAILURE);

        default:
            abort();
        }
    }
    free(short_options);
}

static void
usage(void)
{
    printf("%s: OpenFlow switch management utility\n"
           "usage: %s [OPTIONS] COMMAND [ARG...]\n"
#ifdef HAVE_NETLINK
           "\nFor local datapaths only:\n"
           "  adddp nl:DP_ID              add a new local datapath DP_ID\n"
           "  deldp nl:DP_ID              delete local datapath DP_ID\n"
           "  addif nl:DP_ID IFACE...     add each IFACE as a port on DP_ID\n"
           "  delif nl:DP_ID IFACE...     delete each IFACE from DP_ID\n"
           "  get-idx OF_DEV              get datapath index for OF_DEV\n"
#endif
           "\nFor local datapaths and remote switches:\n"
           "  show SWITCH                 show basic information\n"
           "  status SWITCH [KEY]         report statistics (about KEY)\n"
           "  show-protostat SWITCH       report protocol statistics\n"
           "  dump-desc SWITCH            print switch description\n"
           "  dump-tables SWITCH          print table stats\n"
           "  mod-port SWITCH IFACE ACT   modify port behavior\n"
           "  dump-ports SWITCH           print port statistics\n"
           "  dump-flows SWITCH           print all flow entries\n"
           "  dump-flows SWITCH FLOW      print matching FLOWs\n"
           "  dump-aggregate SWITCH       print aggregate flow statistics\n"
           "  dump-aggregate SWITCH FLOW  print aggregate stats for FLOWs\n"
           "  add-flow SWITCH FLOW        add flow described by FLOW\n"
           "  add-flows SWITCH FILE       add flows from FILE\n"
           "  mod-flows SWITCH FLOW       modify actions of matching FLOWs\n"
           "  del-flows SWITCH [FLOW]     delete matching FLOWs\n"
           "  monitor SWITCH              print packets received from SWITCH\n"
           "  execute SWITCH CMD [ARG...] execute CMD with ARGS on SWITCH\n"
           "\nFor local datapaths, remote switches, and controllers:\n"
           "  probe VCONN                 probe whether VCONN is up\n"
           "  ping VCONN [N]              latency of N-byte echos\n"
           "  benchmark VCONN N COUNT     bandwidth of COUNT N-byte echos\n"
           "where each SWITCH is an active OpenFlow connection method.\n",
           program_name, program_name);
    vconn_usage(true, false, false);
    vlog_usage();
    printf("\nOther options:\n"
           "  --strict                    use strict match for flow commands\n"
           "  -t, --timeout=SECS          give up after SECS seconds\n"
           "  -h, --help                  display this help message\n"
           "  -V, --version               display version information\n");
    exit(EXIT_SUCCESS);
}

static void run(int retval, const char *message, ...)
    PRINTF_FORMAT(2, 3);

static void run(int retval, const char *message, ...)
{
    if (retval) {
        va_list args;

        fprintf(stderr, "%s: ", program_name);
        va_start(args, message);
        vfprintf(stderr, message, args);
        va_end(args);
        if (retval == EOF) {
            fputs(": unexpected end of file\n", stderr);
        } else {
            fprintf(stderr, ": %s\n", strerror(retval));
        }

        exit(EXIT_FAILURE);
    }
}


#ifdef HAVE_NETLINK
/* Netlink-only commands. */

static int if_up(const char *netdev_name)
{
    struct netdev *netdev;
    int retval;

    retval = netdev_open(netdev_name, NETDEV_ETH_TYPE_NONE, &netdev);
    if (!retval) {
        retval = netdev_turn_flags_on(netdev, NETDEV_UP, true);
        netdev_close(netdev);
    }
    return retval;
}

static void
do_get_idx(const struct settings *s UNUSED, int argc UNUSED, char *argv[])
{
    int dp_idx;

    struct dpif dpif;
    run(dpif_open(-1, &dpif), "opening management socket");
    dp_idx = dpif_get_idx(argv[1]);
    if (dp_idx == -1) {
        dpif_close(&dpif);
        ofp_fatal(0, "unknown OpenFlow device: %s", argv[1]);
    }
    printf("%d\n", dp_idx);
    dpif_close(&dpif);
}

static int
get_dp_idx(const char *name)
{
    if (strncmp(name, "nl:", 3)
        || strlen(name) < 4
        || name[strspn(name + 3, "0123456789") + 3]) {
        ofp_fatal(0, "%s: argument is not of the form \"nl:DP_ID\"", name);
    }
    return atoi(name + 3);
}

static void
do_add_dp(const struct settings *s UNUSED, int argc UNUSED, char *argv[])
{
    struct dpif dpif;
    run(dpif_open(-1, &dpif), "opening management socket");
    run(dpif_add_dp(&dpif, get_dp_idx(argv[1]), NULL), "add_dp");
    dpif_close(&dpif);
}

static void
do_del_dp(const struct settings *s UNUSED, int argc UNUSED, char *argv[])
{
    struct dpif dpif;
    run(dpif_open(-1, &dpif), "opening management socket");
    run(dpif_del_dp(&dpif, get_dp_idx(argv[1]), NULL), "del_dp");
    dpif_close(&dpif);
}

static void add_del_ports(int argc UNUSED, char *argv[],
                          int (*function)(struct dpif *, int dp_idx,
                                          const char *netdev),
                          const char *operation, const char *preposition)
{
    bool failure = false;
    struct dpif dpif;
    int dp_idx;
    int i;

    run(dpif_open(-1, &dpif), "opening management socket");
    dp_idx = get_dp_idx(argv[1]);
    for (i = 2; i < argc; i++) {
        int retval = function(&dpif, dp_idx, argv[i]);
        if (retval) {
            ofp_error(retval, "failed to %s %s %s %s",
                      operation, argv[i], preposition, argv[1]);
            failure = true;
        }
    }
    dpif_close(&dpif);
    if (failure) {
        exit(EXIT_FAILURE);
    }
}

static int ifup_and_add_port(struct dpif *dpif, int dp_idx, const char *netdev)
{
    int retval = if_up(netdev);
    return retval ? retval : dpif_add_port(dpif, dp_idx, netdev);
}

static void do_add_port(const struct settings *s UNUSED, int argc UNUSED, 
        char *argv[])
{
    add_del_ports(argc, argv, ifup_and_add_port, "add", "to");
}

static void do_del_port(const struct settings *s UNUSED, int argc UNUSED, 
        char *argv[])
{
    add_del_ports(argc, argv, dpif_del_port, "remove", "from");
}
#endif /* HAVE_NETLINK */

/* Generic commands. */

static void
open_vconn(const char *name, struct vconn **vconnp)
{
    run(vconn_open_block(name, OFP_VERSION, vconnp), "connecting to %s", name);
}

static void *
alloc_stats_request(size_t body_len, uint16_t type, struct ofpbuf **bufferp)
{
    struct ofp_stats_request *rq;
    rq = make_openflow((offsetof(struct ofp_stats_request, body)
                        + body_len), OFPT_STATS_REQUEST, bufferp);
    rq->type = htons(type);
    rq->flags = htons(0);
    return rq->body;
}

static void
send_openflow_buffer(struct vconn *vconn, struct ofpbuf *buffer)
{
    update_openflow_length(buffer);
    run(vconn_send_block(vconn, buffer), "failed to send packet to switch");
}

static void
dump_transaction(const char *vconn_name, struct ofpbuf *request)
{
    struct vconn *vconn;
    struct ofpbuf *reply;

    update_openflow_length(request);
    open_vconn(vconn_name, &vconn);
    run(vconn_transact(vconn, request, &reply), "talking to %s", vconn_name);
    ofp_print(stdout, reply->data, reply->size, 1);
    vconn_close(vconn);
}

static void
dump_trivial_transaction(const char *vconn_name, uint8_t request_type)
{
    struct ofpbuf *request;
    make_openflow(sizeof(struct ofp_header), request_type, &request);
    dump_transaction(vconn_name, request);
}

static void
dump_stats_transaction(const char *vconn_name, struct ofpbuf *request)
{
    uint32_t send_xid = ((struct ofp_header *) request->data)->xid;
    struct vconn *vconn;
    bool done = false;
    
    open_vconn(vconn_name, &vconn);
    send_openflow_buffer(vconn, request);
    while (!done) {
        uint32_t recv_xid;
        struct ofpbuf *reply;

        run(vconn_recv_block(vconn, &reply), "OpenFlow packet receive failed");

        recv_xid = ((struct ofp_header *) reply->data)->xid;
        if (send_xid == recv_xid) {
            struct ofp_stats_reply *osr;
          
            ofp_print(stdout, reply->data, reply->size, 1);

            osr = ofpbuf_at(reply, 0, sizeof *osr);
            done = !osr || !(ntohs(osr->flags) & OFPSF_REPLY_MORE);
        } else {
            VLOG_DBG("received reply with xid %08"PRIx32" "
                     "!= expected %08"PRIx32, recv_xid, send_xid);
        }
        ofpbuf_delete(reply);
    }
    vconn_close(vconn);
}

static void
dump_trivial_stats_transaction(const char *vconn_name, uint8_t stats_type)
{
    struct ofpbuf *request;
    alloc_stats_request(0, stats_type, &request);
    dump_stats_transaction(vconn_name, request);
}

static void
do_show(const struct settings *s UNUSED, int argc UNUSED, char *argv[])
{
  dump_trivial_transaction(argv[1], OFPT_FEATURES_REQUEST);
  dump_trivial_transaction(argv[1], OFPT_GET_CONFIG_REQUEST);
}

static void
do_status(const struct settings *s UNUSED, int argc, char *argv[])
{
    struct nicira_header *request, *reply;
    struct vconn *vconn;
    struct ofpbuf *b;

    request = make_openflow(sizeof *request, OFPT_VENDOR, &b);
    request->vendor = htonl(NX_VENDOR_ID);
    request->subtype = htonl(NXT_STATUS_REQUEST);
    if (argc > 2) {
        ofpbuf_put(b, argv[2], strlen(argv[2]));
    }
    open_vconn(argv[1], &vconn);
    run(vconn_transact(vconn, b, &b), "talking to %s", argv[1]);
    vconn_close(vconn);

    if (b->size < sizeof *reply) {
        ofp_fatal(0, "short reply (%zu bytes)", b->size);
    }
    reply = b->data;
    if (reply->header.type != OFPT_VENDOR
        || reply->vendor != ntohl(NX_VENDOR_ID)
        || reply->subtype != ntohl(NXT_STATUS_REPLY)) {
        ofp_print(stderr, b->data, b->size, 2);
        ofp_fatal(0, "bad reply");
    }

    fwrite(reply + 1, b->size, 1, stdout);
}

static void
print_protocol_stat(struct ofpstat *ofps_rcvd, struct ofpstat *ofps_sent)
{
    int i;
    struct ofpstat *ifps = NULL;
#define PREFIX_STR  "      "
#define PREFIX_RCVD "Rcvd: "
#define PREFIX_SENT "Sent: "

    fprintf(stdout,
            "OpenFlow protocol version 0x%x statisical information\n",
            OFP_VERSION);
    fprintf(stdout, "\n");

    fprintf(stdout, "Protocol message:\n");
    for (i = 0; i < 2; ++i) {
        ifps = i == 0 ? ofps_rcvd : ofps_sent;
        fprintf(stdout,
                "%s"
                "%"PRIu64" total msgs, %"PRIu64" unknown msgs\n",
                i == 0 ? PREFIX_RCVD : PREFIX_SENT,
                ntohll(ifps->ofps_total),
                ntohll(ifps->ofps_unknown));
        fprintf(stdout,
                PREFIX_STR
                "%"PRIu64" hello, %"PRIu64" errors, "
                "%"PRIu64" echo, %"PRIu64" echo reply, "
                "%"PRIu64" vendor\n",
                ntohll(ifps->ofps_hello),
                ntohll(ifps->ofps_error),
                ntohll(ifps->ofps_echo_request),
                ntohll(ifps->ofps_echo_reply),
                ntohll(ifps->ofps_vendor));
        fprintf(stdout,
                PREFIX_STR
                "%"PRIu64" feats, %"PRIu64" feats reply\n",
                ntohll(ifps->ofps_feats_request),
                ntohll(ifps->ofps_feats_reply));
        fprintf(stdout,
                PREFIX_STR
                "%"PRIu64" get config, %"PRIu64" get config reply, "
                "%"PRIu64" set config\n",
                ntohll(ifps->ofps_get_config_request),
                ntohll(ifps->ofps_get_config_reply),
                ntohll(ifps->ofps_set_config));
        fprintf(stdout,
                PREFIX_STR
                "%"PRIu64" packet in, %"PRIu64" flow removed, "
                "%"PRIu64" port status\n",
                ntohll(ifps->ofps_packet_in),
                ntohll(ifps->ofps_flow_removed),
                ntohll(ifps->ofps_port_status));
        fprintf(stdout,
                PREFIX_STR
                "%"PRIu64" packet out, %"PRIu64" flow mod, %"PRIu64" port mod\n",
                ntohll(ifps->ofps_packet_out),
                ntohll(ifps->ofps_flow_mod),
                ntohll(ifps->ofps_port_mod));
        fprintf(stdout,
                PREFIX_STR
                "%"PRIu64" stats, %"PRIu64" stats reply, "
                "%"PRIu64" barrier, %"PRIu64" barrier reply\n",
                ntohll(ifps->ofps_stats_request),
                ntohll(ifps->ofps_stats_reply),
                ntohll(ifps->ofps_barrier_request),
                ntohll(ifps->ofps_barrier_reply));
    }
    fprintf(stdout, "\n");

    fprintf(stdout, "Flow manipulation:\n");
    for (i = 0; i < 2; ++i) {
        ifps = i == 0 ? ofps_rcvd : ofps_sent;
        fprintf(stdout,
                "%s"
                "%"PRIu64" add, %"PRIu64" modify, %"PRIu64" modify strict\n",
                i == 0 ? PREFIX_RCVD : PREFIX_SENT,
                ntohll(ifps->ofps_flow_mod_ops.add),
                ntohll(ifps->ofps_flow_mod_ops.modify),
                ntohll(ifps->ofps_flow_mod_ops.modify_strict));
        fprintf(stdout,
                PREFIX_STR
                "%"PRIu64" delete, %"PRIu64" delete strict, %"PRIu64" unknown cmd\n",
                ntohll(ifps->ofps_flow_mod_ops.delete),
                ntohll(ifps->ofps_flow_mod_ops.delete_strict),
                ntohll(ifps->ofps_flow_mod_ops.unknown));
    }
    fprintf(stdout, "\n");

    fprintf(stdout, "Error notification:\n");
    for (i = 0; i < 2; ++i) {
        ifps = i == 0 ? ofps_rcvd : ofps_sent;
        fprintf(stdout,
                "%s"
                "%"PRIu64" hello fail: %"PRIu64" incompat, %"PRIu64" eperm\n",
                i == 0 ? PREFIX_RCVD : PREFIX_SENT,
                ntohll(ifps->ofps_error_type.hello_fail),
                ntohll(ifps->ofps_error_code.hf_incompat),
                ntohll(ifps->ofps_error_code.hf_eperm));
        fprintf(stdout,
                PREFIX_STR
                "%"PRIu64" bad request: %"PRIu64" version, %"PRIu64" type, "
                "%"PRIu64" stat, %"PRIu64" vendor\n"
                PREFIX_STR
                "    %"PRIu64" eperm\n",
                ntohll(ifps->ofps_error_type.bad_request),
                ntohll(ifps->ofps_error_code.br_bad_version),
                ntohll(ifps->ofps_error_code.br_bad_type),
                ntohll(ifps->ofps_error_code.br_bad_stat),
                ntohll(ifps->ofps_error_code.br_bad_vendor),
                ntohll(ifps->ofps_error_code.br_eperm));
        fprintf(stdout,
                PREFIX_STR
                "%"PRIu64" bad action: %"PRIu64" type, %"PRIu64" len, "
                "%"PRIu64" vendor, %"PRIu64" vendor type\n"
                PREFIX_STR
                "    %"PRIu64" out port, %"PRIu64" argument, %"PRIu64" eperm\n",
                ntohll(ifps->ofps_error_type.bad_action),
                ntohll(ifps->ofps_error_code.ba_bad_type),
                ntohll(ifps->ofps_error_code.ba_bad_len),
                ntohll(ifps->ofps_error_code.ba_bad_vendor),
                ntohll(ifps->ofps_error_code.ba_bad_vendor_type),
                ntohll(ifps->ofps_error_code.ba_bad_out_port),
                ntohll(ifps->ofps_error_code.ba_bad_argument),
                ntohll(ifps->ofps_error_code.ba_eperm));
        fprintf(stdout,
                PREFIX_STR
                "%"PRIu64" flow mod fail: %"PRIu64" all tables full, "
                "%"PRIu64" overlap, %"PRIu64" eperm, %"PRIu64" emerg\n",
                ntohll(ifps->ofps_error_type.flow_mod_fail),
                ntohll(ifps->ofps_error_code.fmf_all_tables_full),
                ntohll(ifps->ofps_error_code.fmf_overlap),
                ntohll(ifps->ofps_error_code.fmf_eperm),
                ntohll(ifps->ofps_error_code.fmf_emerg));
        fprintf(stdout,
                PREFIX_STR
                "%"PRIu64" unknown type, %"PRIu64" unknown code\n",
                ntohll(ifps->ofps_error_type.unknown),
                ntohll(ifps->ofps_error_code.unknown));
    }
    fprintf(stdout, "\n");
}

static void
do_protostat(const struct settings *s UNUSED, int argc UNUSED, char *argv[])
{
    struct ofpbuf *buf;
    struct private_vxhdr *vxhdr;
    struct private_vxopt *vxopt;
    struct vconn *vconn;
    struct ofpstat* ofps;

    vxhdr = make_openflow(sizeof(*vxhdr) + sizeof(*vxopt), OFPT_VENDOR, &buf);
    vxopt = (struct private_vxopt *)(vxhdr + 1);
    vxhdr->ofp_vxid = htonl(PRIVATE_VENDOR_ID);
    vxopt->pvo_type = htons(PRIVATEOPT_PROTOCOL_STATS_REQUEST);
    vxopt->pvo_len = 0;

    open_vconn(argv[1], &vconn);
    run(vconn_transact(vconn, buf, &buf), "talking to %s", argv[1]);
    vconn_close(vconn);
    if (buf->size < sizeof(*vxhdr)) {
        ofp_fatal(0, "short reply (%zu bytes)", buf->size);
    }

    vxhdr = buf->data;
    if (vxhdr->ofp_hdr.type != OFPT_VENDOR
        || ntohl(vxhdr->ofp_vxid) != PRIVATE_VENDOR_ID) {
        ofp_print(stderr, buf->data, buf->size, 2);
        ofp_fatal(0, "bad reply");
    }
    vxopt = (struct private_vxopt *)(vxhdr + 1);
    if (ntohs(vxopt->pvo_type) != PRIVATEOPT_PROTOCOL_STATS_REPLY
        || ntohs(vxopt->pvo_len) != (sizeof(*ofps) * 2)) {
        ofp_print(stderr, buf->data, buf->size, 2);
        ofp_fatal(0, "bad reply");
    }

    ofps = (struct ofpstat *)(vxopt + 1);
    print_protocol_stat(ofps, ofps + 1);
}

static void
do_dump_desc(const struct settings *s UNUSED, int argc UNUSED, char *argv[])
{
    dump_trivial_stats_transaction(argv[1], OFPST_DESC);
}

static void
do_dump_tables(const struct settings *s UNUSED, int argc UNUSED, char *argv[])
{
  dump_trivial_stats_transaction(argv[1], OFPST_TABLE);
}

static uint32_t
str_to_u32(const char *str)
{
    char *tail;
    uint32_t value;

    errno = 0;
    value = strtoul(str, &tail, 0);
    if (errno == EINVAL || errno == ERANGE || *tail) {
        ofp_fatal(0, "invalid numeric format %s", str);
    }
    return value;
}

static void
str_to_mac(const char *str, uint8_t mac[6]) 
{
    if (sscanf(str, "%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8,
               &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 6) {
        ofp_fatal(0, "invalid mac address %s", str);
    }
}

static uint32_t
str_to_ip(const char *str_, uint32_t *ip)
{
    char *str = xstrdup(str_);
    char *save_ptr = NULL;
    const char *name, *netmask;
    struct in_addr in_addr;
    int n_wild, retval;

    name = strtok_r(str, "//", &save_ptr);
    retval = name ? lookup_ip(name, &in_addr) : EINVAL;
    if (retval) {
        ofp_fatal(0, "%s: could not convert to IP address", str);
    }
    *ip = in_addr.s_addr;

    netmask = strtok_r(NULL, "//", &save_ptr);
    if (netmask) {
        uint8_t o[4];
        if (sscanf(netmask, "%"SCNu8".%"SCNu8".%"SCNu8".%"SCNu8,
                   &o[0], &o[1], &o[2], &o[3]) == 4) {
            uint32_t nm = (o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3];
            int i;

            /* Find first 1-bit. */
            for (i = 0; i < 32; i++) {
                if (nm & (1u << i)) {
                    break;
                }
            }
            n_wild = i;

            /* Verify that the rest of the bits are 1-bits. */
            for (; i < 32; i++) {
                if (!(nm & (1u << i))) {
                    ofp_fatal(0, "%s: %s is not a valid netmask",
                              str, netmask);
                }
            }
        } else {
            int prefix = atoi(netmask);
            if (prefix <= 0 || prefix > 32) {
                ofp_fatal(0, "%s: network prefix bits not between 1 and 32",
                          str);
            }
            n_wild = 32 - prefix;
        }
    } else {
        n_wild = 0;
    }

    free(str);
    return n_wild;
}

static void *
put_action(struct ofpbuf *b, size_t size, uint16_t type)
{
    struct ofp_action_header *ah = ofpbuf_put_zeros(b, size);
    ah->type = htons(type);
    ah->len = htons(size);
    return ah;
}

static struct ofp_action_output *
put_output_action(struct ofpbuf *b, uint16_t port)
{
    struct ofp_action_output *oao = put_action(b, sizeof *oao, OFPAT_OUTPUT);
    oao->port = htons(port);
    return oao;
}

static void
str_to_action(char *str, struct ofpbuf *b)
{
    char *act, *arg;
    char *saveptr = NULL;

    for (act = strtok_r(str, ", \t\r\n", &saveptr); act;
         act = strtok_r(NULL, ", \t\r\n", &saveptr)) 
    {
        /* Arguments are separated by colons */
        arg = strchr(act, ':');
        if (arg) {
            *arg = '\0';
            arg++;
        }

        if (!strcasecmp(act, "mod_nw_tos")) {
            struct ofp_action_nw_tos *va;
            va = put_action(b, sizeof *va, OFPAT_SET_NW_TOS);
            va->nw_tos = str_to_u32(arg);
        } else if (!strcasecmp(act, "mod_vlan_vid")) {
            struct ofp_action_vlan_vid *va;
            va = put_action(b, sizeof *va, OFPAT_SET_VLAN_VID);
            va->vlan_vid = htons(str_to_u32(arg));
        } else if (!strcasecmp(act, "mod_vlan_pcp")) {
            struct ofp_action_vlan_pcp *va;
            va = put_action(b, sizeof *va, OFPAT_SET_VLAN_PCP);
            va->vlan_pcp = str_to_u32(arg);
        } else if (!strcasecmp(act, "mod_dl_dst")) {
            struct ofp_action_dl_addr *va;
            va = put_action(b, sizeof *va, OFPAT_SET_DL_DST);
            str_to_mac(arg, va->dl_addr);
        } else if (!strcasecmp(act, "mod_dl_src")) {
            struct ofp_action_dl_addr *va;
            va = put_action(b, sizeof *va, OFPAT_SET_DL_SRC);
            str_to_mac(arg, va->dl_addr);
        } else if (!strcasecmp(act, "strip_vlan")) {
            struct ofp_action_header *ah;
            ah = put_action(b, sizeof *ah, OFPAT_STRIP_VLAN);
            ah->type = htons(OFPAT_STRIP_VLAN);
        } else if (!strcasecmp(act, "output")) {
            put_output_action(b, str_to_u32(arg));
        } else if (!strcasecmp(act, "TABLE")) {
            put_output_action(b, OFPP_TABLE);
        } else if (!strcasecmp(act, "NORMAL")) {
            put_output_action(b, OFPP_NORMAL);
        } else if (!strcasecmp(act, "FLOOD")) {
            put_output_action(b, OFPP_FLOOD);
        } else if (!strcasecmp(act, "ALL")) {
            put_output_action(b, OFPP_ALL);
        } else if (!strcasecmp(act, "CONTROLLER")) {
            struct ofp_action_output *oao;
            oao = put_output_action(b, OFPP_CONTROLLER);

            /* Unless a numeric argument is specified, we send the whole
             * packet to the controller. */
            if (arg && (strspn(act, "0123456789") == strlen(act))) {
               oao->max_len = htons(str_to_u32(arg));
            }
        } else if (!strcasecmp(act, "LOCAL")) {
            put_output_action(b, OFPP_LOCAL);
        } else if (strspn(act, "0123456789") == strlen(act)) {
            put_output_action(b, str_to_u32(act));
        } else {
            ofp_fatal(0, "Unknown action: %s", act);
        }
    }
}

struct protocol {
    const char *name;
    uint16_t dl_type;
    uint8_t nw_proto;
};

static bool
parse_protocol(const char *name, const struct protocol **p_out)
{
    static const struct protocol protocols[] = {
        { "ip", ETH_TYPE_IP, 0 },
        { "arp", ETH_TYPE_ARP, 0 },
        { "icmp", ETH_TYPE_IP, IP_TYPE_ICMP },
        { "tcp", ETH_TYPE_IP, IP_TYPE_TCP },
        { "udp", ETH_TYPE_IP, IP_TYPE_UDP },
    };
    const struct protocol *p;

    for (p = protocols; p < &protocols[ARRAY_SIZE(protocols)]; p++) {
        if (!strcmp(p->name, name)) {
            *p_out = p;
            return true;
        }
    }
    *p_out = NULL;
    return false;
}

struct field {
    const char *name;
    uint32_t wildcard;
    enum { F_U8, F_U16, F_MAC, F_IP } type;
    size_t offset, shift;
};

static bool
parse_field(const char *name, const struct field **f_out) 
{
#define F_OFS(MEMBER) offsetof(struct ofp_match, MEMBER)
    static const struct field fields[] = { 
        { "in_port", OFPFW_IN_PORT, F_U16, F_OFS(in_port), 0 },
        { "dl_vlan", OFPFW_DL_VLAN, F_U16, F_OFS(dl_vlan), 0 },
        { "dl_vlan_pcp", OFPFW_DL_VLAN_PCP, F_U8, F_OFS(dl_vlan_pcp), 0 },
        { "dl_src", OFPFW_DL_SRC, F_MAC, F_OFS(dl_src), 0 },
        { "dl_dst", OFPFW_DL_DST, F_MAC, F_OFS(dl_dst), 0 },
        { "dl_type", OFPFW_DL_TYPE, F_U16, F_OFS(dl_type), 0 },
        { "nw_src", OFPFW_NW_SRC_MASK, F_IP,
          F_OFS(nw_src), OFPFW_NW_SRC_SHIFT },
        { "nw_dst", OFPFW_NW_DST_MASK, F_IP,
          F_OFS(nw_dst), OFPFW_NW_DST_SHIFT },
        { "nw_proto", OFPFW_NW_PROTO, F_U8, F_OFS(nw_proto), 0 },
        { "tp_src", OFPFW_TP_SRC, F_U16, F_OFS(tp_src), 0 },
        { "tp_dst", OFPFW_TP_DST, F_U16, F_OFS(tp_dst), 0 },
        { "icmp_type", OFPFW_ICMP_TYPE, F_U16, F_OFS(icmp_type), 0 },
        { "icmp_code", OFPFW_ICMP_CODE, F_U16, F_OFS(icmp_code), 0 }
    };
    const struct field *f;

    for (f = fields; f < &fields[ARRAY_SIZE(fields)]; f++) {
        if (!strcmp(f->name, name)) {
            *f_out = f;
            return true;
        }
    }
    *f_out = NULL;
    return false;
}

static void
str_to_flow(char *string, struct ofp_match *match, struct ofpbuf *actions,
            uint8_t *table_idx, uint16_t *out_port, uint16_t *priority,
            uint16_t *idle_timeout, uint16_t *hard_timeout)
{
    char *save_ptr = NULL;
    char *name;
    uint32_t wildcards;

    if (table_idx) {
        *table_idx = 0xff;
    }
    if (out_port) {
        *out_port = OFPP_NONE;
    }
    if (priority) {
        *priority = OFP_DEFAULT_PRIORITY;
    }
    if (idle_timeout) {
        *idle_timeout = DEFAULT_IDLE_TIMEOUT;
    }
    if (hard_timeout) {
        *hard_timeout = OFP_FLOW_PERMANENT;
    }
    if (actions) {
        char *act_str = strstr(string, "actions");
        if (!act_str) {
            ofp_fatal(0, "must specify an action");
        }
        *(act_str-1) = '\0';

        act_str = strchr(act_str, '=');
        if (!act_str) {
            ofp_fatal(0, "must specify an action");
        }

        act_str++;

        str_to_action(act_str, actions);
    }
    memset(match, 0, sizeof *match);
    wildcards = OFPFW_ALL;
    for (name = strtok_r(string, "=, \t\r\n", &save_ptr); name;
         name = strtok_r(NULL, "=, \t\r\n", &save_ptr)) {
        const struct protocol *p;

        if (parse_protocol(name, &p)) {
            wildcards &= ~OFPFW_DL_TYPE;
            match->dl_type = htons(p->dl_type);
            if (p->nw_proto) {
                wildcards &= ~OFPFW_NW_PROTO;
                match->nw_proto = p->nw_proto;
            }
        } else {
            const struct field *f;
            char *value;

            value = strtok_r(NULL, ", \t\r\n", &save_ptr);
            if (!value) {
                ofp_fatal(0, "field %s missing value", name);
            }

            if (table_idx && !strcmp(name, "table")) {
                *table_idx = atoi(value);
            } else if (out_port && !strcmp(name, "out_port")) {
                *out_port = atoi(value);
            } else if (priority && !strcmp(name, "priority")) {
                *priority = atoi(value);
            } else if (idle_timeout && !strcmp(name, "idle_timeout")) {
                *idle_timeout = atoi(value);
            } else if (hard_timeout && !strcmp(name, "hard_timeout")) {
                *hard_timeout = atoi(value);
            } else if (parse_field(name, &f)) {
                void *data = (char *) match + f->offset;
                if (!strcmp(value, "*") || !strcmp(value, "ANY")) {
                    wildcards |= f->wildcard;
                } else {
                    wildcards &= ~f->wildcard;
                    if (f->type == F_U8) {
                        *(uint8_t *) data = str_to_u32(value);
                    } else if (f->type == F_U16) {
                        *(uint16_t *) data = htons(str_to_u32(value));
                    } else if (f->type == F_MAC) {
                        str_to_mac(value, data);
                    } else if (f->type == F_IP) {
                        wildcards |= str_to_ip(value, data) << f->shift;
                    } else {
                        NOT_REACHED();
                    }
                }
            } else {
                ofp_fatal(0, "unknown keyword %s", name);
            }
        }
    }
    match->wildcards = htonl(wildcards);
}

static void
do_dump_flows(const struct settings *s UNUSED, int argc, char *argv[])
{
    struct ofp_flow_stats_request *req;
    uint16_t out_port;
    struct ofpbuf *request;

    req = alloc_stats_request(sizeof *req, OFPST_FLOW, &request);
    str_to_flow(argc > 2 ? argv[2] : "", &req->match, NULL,
                &req->table_id, &out_port, NULL, NULL, NULL);
    memset(&req->pad, 0, sizeof req->pad);
    req->out_port = htons(out_port);

    dump_stats_transaction(argv[1], request);
}

static void
do_dump_aggregate(const struct settings *s UNUSED, int argc, char *argv[])
{
    struct ofp_aggregate_stats_request *req;
    struct ofpbuf *request;
    uint16_t out_port;

    req = alloc_stats_request(sizeof *req, OFPST_AGGREGATE, &request);
    str_to_flow(argc > 2 ? argv[2] : "", &req->match, NULL,
                &req->table_id, &out_port, NULL, NULL, NULL);
    memset(&req->pad, 0, sizeof req->pad);
    req->out_port = htons(out_port);

    dump_stats_transaction(argv[1], request);
}

#define EMERG_TABLE_ID 0xfe

static void
do_add_flow(const struct settings *s UNUSED, int argc UNUSED, char *argv[])
{
    struct vconn *vconn;
    struct ofpbuf *buffer;
    struct ofp_flow_mod *ofm;
    uint16_t priority, idle_timeout, hard_timeout;
    uint8_t table_id;
    struct ofp_match match;

    /* Parse and send.  str_to_flow() will expand and reallocate the data in
     * 'buffer', so we can't keep pointers to across the str_to_flow() call. */
    make_openflow(sizeof *ofm, OFPT_FLOW_MOD, &buffer);
    str_to_flow(argv[2], &match, buffer,
                &table_id, NULL, &priority, &idle_timeout, &hard_timeout);
    ofm = buffer->data;
    ofm->match = match;
    ofm->command = htons(OFPFC_ADD);
    ofm->idle_timeout = table_id == EMERG_TABLE_ID ? 0 : htons(idle_timeout);
    ofm->hard_timeout = table_id == EMERG_TABLE_ID ? 0 : htons(hard_timeout);
    ofm->buffer_id = htonl(UINT32_MAX);
    ofm->priority = htons(priority);
    ofm->flags = htons(OFPFF_SEND_FLOW_REM);
    if (table_id == EMERG_TABLE_ID)
        ofm->flags |= htons(OFPFF_EMERG);
    ofm->reserved = htonl(0);

    open_vconn(argv[1], &vconn);
    send_openflow_buffer(vconn, buffer);
    vconn_close(vconn);
}

static void
do_add_flows(const struct settings *s UNUSED, int argc UNUSED, char *argv[])
{
    struct vconn *vconn;
    FILE *file;
    char line[1024];

    file = fopen(argv[2], "r");
    if (file == NULL) {
        ofp_fatal(errno, "%s: open", argv[2]);
    }

    open_vconn(argv[1], &vconn);
    while (fgets(line, sizeof line, file)) {
        struct ofpbuf *buffer;
        struct ofp_flow_mod *ofm;
        uint16_t priority, idle_timeout, hard_timeout;
        uint8_t table_id;
        struct ofp_match match;

        char *comment;

        /* Delete comments. */
        comment = strchr(line, '#');
        if (comment) {
            *comment = '\0';
        }

        /* Drop empty lines. */
        if (line[strspn(line, " \t\n")] == '\0') {
            continue;
        }

        /* Parse and send.  str_to_flow() will expand and reallocate the data
         * in 'buffer', so we can't keep pointers to across the str_to_flow()
         * call. */
        ofm = make_openflow(sizeof *ofm, OFPT_FLOW_MOD, &buffer);
        str_to_flow(line, &match, buffer,
                    &table_id, NULL, &priority, &idle_timeout, &hard_timeout);
        ofm = buffer->data;
        ofm->match = match;
        ofm->command = htons(OFPFC_ADD);
        ofm->idle_timeout = table_id == EMERG_TABLE_ID ? 0 : htons(idle_timeout);
        ofm->hard_timeout = table_id == EMERG_TABLE_ID ? 0 : htons(hard_timeout);
        ofm->buffer_id = htonl(UINT32_MAX);
        ofm->priority = htons(priority);
        ofm->flags = htons(OFPFF_SEND_FLOW_REM);
        if (table_id == EMERG_TABLE_ID)
            ofm->flags |= htons(OFPFF_EMERG);
        ofm->reserved = htonl(0);

        send_openflow_buffer(vconn, buffer);
    }
    vconn_close(vconn);
    fclose(file);
}

static void
do_mod_flows(const struct settings *s, int argc UNUSED, char *argv[])
{
    uint16_t priority, idle_timeout, hard_timeout;
    uint8_t table_id;
    struct vconn *vconn;
    struct ofpbuf *buffer;
    struct ofp_flow_mod *ofm;

    /* Parse and send. */
    ofm = make_openflow(sizeof *ofm, OFPT_FLOW_MOD, &buffer);
    str_to_flow(argv[2], &ofm->match, buffer,
                &table_id, NULL, &priority, &idle_timeout, &hard_timeout);
    if (s->strict) {
        ofm->command = htons(OFPFC_MODIFY_STRICT);
    } else {
        ofm->command = htons(OFPFC_MODIFY);
    }
    ofm->idle_timeout = table_id == EMERG_TABLE_ID ? 0 : htons(idle_timeout);
    ofm->hard_timeout = table_id == EMERG_TABLE_ID ? 0 : htons(hard_timeout);
    ofm->buffer_id = htonl(UINT32_MAX);
    if (table_id == EMERG_TABLE_ID)
        ofm->flags = htons(OFPFF_EMERG);
    ofm->priority = htons(priority);
    ofm->reserved = htonl(0);

    open_vconn(argv[1], &vconn);
    send_openflow_buffer(vconn, buffer);
    vconn_close(vconn);
}

static void do_del_flows(const struct settings *s, int argc, char *argv[])
{
    struct vconn *vconn;
    uint16_t priority;
    uint16_t out_port;
    uint8_t table_id;
    struct ofpbuf *buffer;
    struct ofp_flow_mod *ofm;

    /* Parse and send. */
    ofm = make_openflow(sizeof *ofm, OFPT_FLOW_MOD, &buffer);
    str_to_flow(argc > 2 ? argv[2] : "", &ofm->match, NULL,
                &table_id, &out_port, &priority, NULL, NULL);
    if (s->strict) {
        ofm->command = htons(OFPFC_DELETE_STRICT);
    } else {
        ofm->command = htons(OFPFC_DELETE);
    }
    ofm->idle_timeout = htons(0);
    ofm->hard_timeout = htons(0);
    ofm->buffer_id = htonl(UINT32_MAX);
    if (table_id == EMERG_TABLE_ID)
        ofm->flags = htons(OFPFF_EMERG);
    ofm->out_port = htons(out_port);
    ofm->priority = htons(priority);
    ofm->reserved = htonl(0);

    open_vconn(argv[1], &vconn);
    send_openflow_buffer(vconn, buffer);
    vconn_close(vconn);
}

static void
do_monitor(const struct settings *s UNUSED, int argc UNUSED, char *argv[])
{
    struct vconn *vconn;
    const char *name;

    /* If the user specified, e.g., "nl:0", append ":1" to it to ensure that
     * the connection will subscribe to listen for asynchronous messages, such
     * as packet-in messages. */
    if (!strncmp(argv[1], "nl:", 3) && strrchr(argv[1], ':') == &argv[1][2]) {
        name = xasprintf("%s:1", argv[1]);
    } else {
        name = argv[1];
    }
    open_vconn(argv[1], &vconn);
    for (;;) {
        struct ofpbuf *b;
        run(vconn_recv_block(vconn, &b), "vconn_recv");
        ofp_print(stderr, b->data, b->size, 2);
        ofpbuf_delete(b);
    }
}

static void
do_dump_ports(const struct settings *s UNUSED, int argc UNUSED, char *argv[])
{
    dump_trivial_stats_transaction(argv[1], OFPST_PORT);
}

static void
do_probe(const struct settings *s UNUSED, int argc UNUSED, char *argv[])
{
    struct ofpbuf *request;
    struct vconn *vconn;
    struct ofpbuf *reply;

    make_openflow(sizeof(struct ofp_header), OFPT_ECHO_REQUEST, &request);
    open_vconn(argv[1], &vconn);
    run(vconn_transact(vconn, request, &reply), "talking to %s", argv[1]);
    if (reply->size != sizeof(struct ofp_header)) {
        ofp_fatal(0, "reply does not match request");
    }
    ofpbuf_delete(reply);
    vconn_close(vconn);
}

static void
do_mod_port(const struct settings *s UNUSED, int argc UNUSED, char *argv[])
{
    struct ofpbuf *request, *reply;
    struct ofp_switch_features *osf;
    struct ofp_port_mod *opm;
    struct vconn *vconn;
    char *endptr;
    int n_ports;
    int port_idx;
    int port_no;
    

    /* Check if the argument is a port index.  Otherwise, treat it as
     * the port name. */
    port_no = strtol(argv[2], &endptr, 10);
    if (port_no == 0 && endptr == argv[2]) {
        port_no = -1;
    }

    /* Send a "Features Request" to get the information we need in order 
     * to modify the port. */
    make_openflow(sizeof(struct ofp_header), OFPT_FEATURES_REQUEST, &request);
    open_vconn(argv[1], &vconn);
    run(vconn_transact(vconn, request, &reply), "talking to %s", argv[1]);

    osf = reply->data;
    n_ports = (reply->size - sizeof *osf) / sizeof *osf->ports;

    for (port_idx = 0; port_idx < n_ports; port_idx++) {
        if (port_no != -1) {
            /* Check argument as a port index */
            if (osf->ports[port_idx].port_no == htons(port_no)) {
                break;
            }
        } else {
            /* Check argument as an interface name */
            if (!strncmp((char *)osf->ports[port_idx].name, argv[2], 
                        sizeof osf->ports[0].name)) {
                break;
            }

        }
    }
    if (port_idx == n_ports) {
        ofp_fatal(0, "couldn't find monitored port: %s", argv[2]);
    }

    opm = make_openflow(sizeof(struct ofp_port_mod), OFPT_PORT_MOD, &request);
    opm->port_no = osf->ports[port_idx].port_no;
    memcpy(opm->hw_addr, osf->ports[port_idx].hw_addr, sizeof opm->hw_addr);
    opm->config = htonl(0);
    opm->mask = htonl(0);
    opm->advertise = htonl(0);

    printf("modifying port: %s\n", osf->ports[port_idx].name);

    if (!strncasecmp(argv[3], MOD_PORT_CMD_UP, sizeof MOD_PORT_CMD_UP)) {
        opm->mask |= htonl(OFPPC_PORT_DOWN);
    } else if (!strncasecmp(argv[3], MOD_PORT_CMD_DOWN, 
                sizeof MOD_PORT_CMD_DOWN)) {
        opm->mask |= htonl(OFPPC_PORT_DOWN);
        opm->config |= htonl(OFPPC_PORT_DOWN);
    } else if (!strncasecmp(argv[3], MOD_PORT_CMD_FLOOD, 
                sizeof MOD_PORT_CMD_FLOOD)) {
        opm->mask |= htonl(OFPPC_NO_FLOOD);
    } else if (!strncasecmp(argv[3], MOD_PORT_CMD_NOFLOOD, 
                sizeof MOD_PORT_CMD_NOFLOOD)) {
        opm->mask |= htonl(OFPPC_NO_FLOOD);
        opm->config |= htonl(OFPPC_NO_FLOOD);
    } else {
        ofp_fatal(0, "unknown mod-port command '%s'", argv[3]);
    }

    send_openflow_buffer(vconn, request);

    ofpbuf_delete(reply);
    vconn_close(vconn);
}

static void
do_ping(const struct settings *s UNUSED, int argc, char *argv[])
{
    size_t max_payload = 65535 - sizeof(struct ofp_header);
    unsigned int payload;
    struct vconn *vconn;
    int i;

    payload = argc > 2 ? atoi(argv[2]) : 64;
    if (payload > max_payload) {
        ofp_fatal(0, "payload must be between 0 and %zu bytes", max_payload);
    }

    open_vconn(argv[1], &vconn);
    for (i = 0; i < 10; i++) {
        struct timeval start, end;
        struct ofpbuf *request, *reply;
        struct ofp_header *rq_hdr, *rpy_hdr;

        rq_hdr = make_openflow(sizeof(struct ofp_header) + payload,
                               OFPT_ECHO_REQUEST, &request);
        random_bytes(rq_hdr + 1, payload);

        gettimeofday(&start, NULL);
        run(vconn_transact(vconn, ofpbuf_clone(request), &reply), "transact");
        gettimeofday(&end, NULL);

        rpy_hdr = reply->data;
        if (reply->size != request->size
            || memcmp(rpy_hdr + 1, rq_hdr + 1, payload)
            || rpy_hdr->xid != rq_hdr->xid
            || rpy_hdr->type != OFPT_ECHO_REPLY) {
            printf("Reply does not match request.  Request:\n");
            ofp_print(stdout, request, request->size, 2);
            printf("Reply:\n");
            ofp_print(stdout, reply, reply->size, 2);
        }
        printf("%d bytes from %s: xid=%08"PRIx32" time=%.1f ms\n",
               reply->size - sizeof *rpy_hdr, argv[1], rpy_hdr->xid,
                   (1000*(double)(end.tv_sec - start.tv_sec))
                   + (.001*(end.tv_usec - start.tv_usec)));
        ofpbuf_delete(request);
        ofpbuf_delete(reply);
    }
    vconn_close(vconn);
}

static void
do_benchmark(const struct settings *s UNUSED, int argc UNUSED, char *argv[])
{
    size_t max_payload = 65535 - sizeof(struct ofp_header);
    struct timeval start, end;
    unsigned int payload_size, message_size;
    struct vconn *vconn;
    double duration;
    int count;
    int i;

    payload_size = atoi(argv[2]);
    if (payload_size > max_payload) {
        ofp_fatal(0, "payload must be between 0 and %zu bytes", max_payload);
    }
    message_size = sizeof(struct ofp_header) + payload_size;

    count = atoi(argv[3]);

    printf("Sending %d packets * %u bytes (with header) = %u bytes total\n",
           count, message_size, count * message_size);

    open_vconn(argv[1], &vconn);
    gettimeofday(&start, NULL);
    for (i = 0; i < count; i++) {
        struct ofpbuf *request, *reply;
        struct ofp_header *rq_hdr;

        rq_hdr = make_openflow(message_size, OFPT_ECHO_REQUEST, &request);
        memset(rq_hdr + 1, 0, payload_size);
        run(vconn_transact(vconn, request, &reply), "transact");
        ofpbuf_delete(reply);
    }
    gettimeofday(&end, NULL);
    vconn_close(vconn);

    duration = ((1000*(double)(end.tv_sec - start.tv_sec))
                + (.001*(end.tv_usec - start.tv_usec)));
    printf("Finished in %.1f ms (%.0f packets/s) (%.0f bytes/s)\n",
           duration, count / (duration / 1000.0),
           count * message_size / (duration / 1000.0));
}

static void
do_execute(const struct settings *s UNUSED, int argc, char *argv[])
{
    struct vconn *vconn;
    struct ofpbuf *request;
    struct nicira_header *nicira;
    struct nx_command_reply *ncr;
    uint32_t xid;
    int i;

    nicira = make_openflow(sizeof *nicira, OFPT_VENDOR, &request);
    xid = nicira->header.xid;
    nicira->vendor = htonl(NX_VENDOR_ID);
    nicira->subtype = htonl(NXT_COMMAND_REQUEST);
    ofpbuf_put(request, argv[2], strlen(argv[2]));
    for (i = 3; i < argc; i++) {
        ofpbuf_put_zeros(request, 1);
        ofpbuf_put(request, argv[i], strlen(argv[i]));
    }
    update_openflow_length(request);

    open_vconn(argv[1], &vconn);
    run(vconn_send_block(vconn, request), "send");

    for (;;) {
        struct ofpbuf *reply;
        uint32_t status;

        run(vconn_recv_xid(vconn, xid, &reply), "recv_xid");
        if (reply->size < sizeof *ncr) {
            ofp_fatal(0, "reply is too short (%zu bytes < %zu bytes)",
                      reply->size, sizeof *ncr);
        }
        ncr = reply->data;
        if (ncr->nxh.header.type != OFPT_VENDOR
            || ncr->nxh.vendor != htonl(NX_VENDOR_ID)
            || ncr->nxh.subtype != htonl(NXT_COMMAND_REPLY)) {
            ofp_fatal(0, "reply is invalid");
        }

        status = ntohl(ncr->status);
        if (status & NXT_STATUS_STARTED) {
            /* Wait for a second reply. */
            continue;
        } else if (status & NXT_STATUS_EXITED) {
            fprintf(stderr, "process terminated normally with exit code %d",
                    status & NXT_STATUS_EXITSTATUS);
        } else if (status & NXT_STATUS_SIGNALED) {
            fprintf(stderr, "process terminated by signal %d",
                    status & NXT_STATUS_TERMSIG);
        } else if (status & NXT_STATUS_ERROR) {
            fprintf(stderr, "error executing command");
        } else {
            fprintf(stderr, "process terminated for unknown reason");
        }
        if (status & NXT_STATUS_COREDUMP) {
            fprintf(stderr, " (core dumped)");
        }
        putc('\n', stderr);

        fwrite(ncr + 1, reply->size - sizeof *ncr, 1, stdout);
        break;
    }
}

static void
do_help(const struct settings *s UNUSED, int argc UNUSED, char *argv[] UNUSED)
{
    usage();
}

static struct command all_commands[] = {
#ifdef HAVE_NETLINK
    { "adddp", 1, 1, do_add_dp },
    { "deldp", 1, 1, do_del_dp },
    { "addif", 2, INT_MAX, do_add_port },
    { "delif", 2, INT_MAX, do_del_port },
    { "get-idx", 1, 1, do_get_idx },
#endif

    { "show", 1, 1, do_show },
    { "status", 1, 2, do_status },

    { "show-protostat", 1, 1, do_protostat },

    { "help", 0, INT_MAX, do_help },
    { "monitor", 1, 1, do_monitor },
    { "dump-desc", 1, 1, do_dump_desc },
    { "dump-tables", 1, 1, do_dump_tables },
    { "dump-flows", 1, 2, do_dump_flows },
    { "dump-aggregate", 1, 2, do_dump_aggregate },
    { "add-flow", 2, 2, do_add_flow },
    { "add-flows", 2, 2, do_add_flows },
    { "mod-flows", 2, 2, do_mod_flows },
    { "del-flows", 1, 2, do_del_flows },
    { "dump-ports", 1, 1, do_dump_ports },
    { "mod-port", 3, 3, do_mod_port },
    { "probe", 1, 1, do_probe },
    { "ping", 1, 2, do_ping },
    { "benchmark", 3, 3, do_benchmark },
    { "execute", 2, INT_MAX, do_execute },
    { NULL, 0, 0, NULL },
};
