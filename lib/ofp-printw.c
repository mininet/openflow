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

#include "ofp-printw.h"
#include "xtoxll.h"

#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <sys/wait.h>
#include <stdarg.h>
#include <stdlib.h>
#include <ctype.h>
#include <curses.h>

#include "compiler.h"
#include "dynamic-string.h"
#include "util.h"
#include "openflow.h"
#include "packets.h"

int LAST_PY;

/* Returns a string that represents the contents of the Ethernet frame in the
 * 'len' bytes starting at 'data' to 'stream' as output by tcpdump.
 * 'total_len' specifies the full length of the Ethernet frame (of which 'len'
 * bytes were captured).
 *
 * The caller must free the returned string.
 *
 * This starts and kills a tcpdump subprocess so it's quite expensive. */
/*
char *
ofp_packet_to_string(const void *data, size_t len, size_t total_len)
{
    struct pcap_hdr {
    uint32_t magic_number;   // magic number 

    uint16_t version_major;  // major version number 
    uint16_t version_minor;  // minor version number 
    int32_t thiszone;        // GMT to local correction  
    uint32_t sigfigs;        // accuracy of timestamps 
    uint32_t snaplen;        // max length of captured packets 
    uint32_t network;        // data link type 
    } PACKED;

    struct pcaprec_hdr {
      uint32_t ts_sec;         // timestamp seconds 
      uint32_t ts_usec;        // timestamp microseconds 
      uint32_t incl_len;       // number of octets of packet saved in file 
      uint32_t orig_len;       // actual length of packet 
    } PACKED;

    struct pcap_hdr ph;
    struct pcaprec_hdr prh;

    struct ds ds = DS_EMPTY_INITIALIZER;

    char command[128];
    FILE *pcap;
    FILE *tcpdump;
    int status;
    int c;

    pcap = tmpfile();
    if (!pcap) {
        error(errno, "tmpfile");
        return xstrdup("<error>");
    }

  // The pcap reader is responsible for figuring out endianness based on the
  //   * magic number, so the lack of htonX calls here is intentional.
    ph.magic_number = 0xa1b2c3d4;
    ph.version_major = 2;
    ph.version_minor = 4;
    ph.thiszone = 0;
    ph.sigfigs = 0;
    ph.snaplen = 1518;
    ph.network = 1;             // Ethernet 

    prh.ts_sec = 0;
    prh.ts_usec = 0;
    prh.incl_len = len;
    prh.orig_len = total_len;

    fwrite(&ph, 1, sizeof ph, pcap);
    fwrite(&prh, 1, sizeof prh, pcap);
    fwrite(data, 1, len, pcap);

    fflush(pcap);
    if (ferror(pcap)) {
        error(errno, "error writing temporary file");
    }
    rewind(pcap);

    snprintf(command, sizeof command, "tcpdump -n -r /dev/fd/%d 2>/dev/null",
             fileno(pcap));
    tcpdump = popen(command, "r");
    fclose(pcap);
    if (!tcpdump) {
        error(errno, "exec(\"%s\")", command);
        return xstrdup("<error>");
    }

    while ((c = getc(tcpdump)) != EOF) {
        ds_put_char(&ds, c);
    }

    status = pclose(tcpdump);
    if (WIFEXITED(status)) {
        if (WEXITSTATUS(status))
            error(0, "tcpdump exited with status %d", WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        error(0, "tcpdump exited with signal %d", WTERMSIG(status)); 
    }
    return ds_cstr(&ds);
}
*/

/* Pretty-print the OFPT_PACKET_IN packet of 'len' bytes at 'oh' to 'stream'
 * at the given 'verbosity' level. */
/*
static void
ofp_packet_in(struct ds *string, const void *oh, size_t len, int verbosity)
{
    const struct ofp_packet_in *op = oh;
    size_t data_len;

    ds_put_format(string, " total_len=%"PRIu16" in_port=%"PRIu8,
            ntohs(op->total_len), ntohs(op->in_port));

    if (op->reason == OFPR_ACTION)
        ds_put_cstr(string, " (via action)");
    else if (op->reason != OFPR_NO_MATCH)
        ds_put_format(string, " (***reason %"PRIu8"***)", op->reason);

    data_len = len - offsetof(struct ofp_packet_in, data);
    ds_put_format(string, " data_len=%zu", data_len);
    if (htonl(op->buffer_id) == UINT32_MAX) {
        ds_put_format(string, " (unbuffered)");
        if (ntohs(op->total_len) != data_len)
            ds_put_format(string, " (***total_len != data_len***)");
    } else {
        ds_put_format(string, " buffer=%08"PRIx32, ntohl(op->buffer_id));
        if (ntohs(op->total_len) < data_len)
            ds_put_format(string, " (***total_len < data_len***)");
    }
    ds_put_char(string, '\n');

    if (verbosity > 0) {
        char *packet = ofp_packet_to_string(op->data, data_len,
                                            ntohs(op->total_len)); 
        ds_put_cstr(string, packet);
        free(packet);
    }
}
*/

static void ofp_printw_port_name(struct ds *string, uint16_t port) 
{
    const char *name;
    switch (port) {
    case OFPP_TABLE:
        name = "TABL";
        break;
    case OFPP_NORMAL:
        name = "NRML";
        break;
    case OFPP_FLOOD:
        name = " FLD";
        break;
    case OFPP_ALL:
        name = " ALL";
        break;
    case OFPP_CONTROLLER:
        name = "CTLR";
        break;
    case OFPP_LOCAL:
        name = "LOCL";
        break;
    case OFPP_NONE:
        name = "NONE";
        break;
    default:
      printw("%"PRIu16, port);
        return;
    }
    printw(name);
}

static void
ofp_printw_action(struct ds *string, const struct ofp_action *a) 
{
    switch (ntohs(a->type)) {
    case OFPAT_OUTPUT:
      printw("output(");
        ofp_printw_port_name(string, ntohs(a->arg.output.port));
        if (a->arg.output.port == htons(OFPP_CONTROLLER)) {
          printw(", max %"PRIu16" bytes", ntohs(a->arg.output.max_len));
        }
        printw(")");
        break;

    default:
      printw("(decoder %"PRIu16" not implemented)", ntohs(a->type));
      break;
    }
}

static void ofp_printw_actions(struct ds *string,
                              const struct ofp_action actions[],
                              size_t n_bytes) 
{
    size_t i;
    int y, x;
    getyx(stdscr, y, x);
    mvprintw(y, 96, "[");
    for (i = 0; i < n_bytes / sizeof *actions; i++) {
        if (i) {
          printw("; ");
        }
        ofp_printw_action(string, &actions[i]);
    }
    if (n_bytes % sizeof *actions) {
        if (i) {
          printw("; ");
        }
        printw("; ***trailing garbage***");
    }
    printw("]");
}

/*
// Pretty-print the OFPT_PACKET_OUT packet of 'len' bytes at 'oh' to 'string'
// at the given 'verbosity' level. 
static void ofp_packet_out(struct ds *string, const void *oh, size_t len,
                           int verbosity) 
{
    const struct ofp_packet_out *opo = oh;

    ds_put_cstr(string, " in_port=");
    ofp_print_port_name(string, ntohs(opo->in_port));

    if (ntohl(opo->buffer_id) == UINT32_MAX) {
        ds_put_cstr(string, " out_port=");
        ofp_print_port_name(string, ntohs(opo->out_port));
        if (verbosity > 0 && len > sizeof *opo) {
            char *packet = ofp_packet_to_string(opo->u.data, len - sizeof *opo,
                                                len - sizeof *opo);
            ds_put_cstr(string, packet);
            free(packet);
        }
    } else {
        ds_put_format(string, " buffer=%08"PRIx32, ntohl(opo->buffer_id));
        ofp_print_actions(string, opo->u.actions, len - sizeof *opo);
    }
    ds_put_char(string, '\n');
}
*/
// qsort comparison function. 
static int
compare_portsw(const void *a_, const void *b_)
{
    const struct ofp_phy_port *a = a_;
    const struct ofp_phy_port *b = b_;
    uint16_t ap = ntohs(a->port_no);
    uint16_t bp = ntohs(b->port_no);

    return ap < bp ? -1 : ap > bp;
}

static void
ofp_printw_phy_port(struct ds *string, const struct ofp_phy_port *port)
{
    uint8_t name[OFP_MAX_PORT_NAME_LEN];
    int j;

    memcpy(name, port->name, sizeof name);
    for (j = 0; j < sizeof name - 1; j++) {
        if (!isprint(name[j])) {
            break;
        }
    }
    name[j] = '\0';

    ofp_printw_port_name(string, ntohs(port->port_no));
    printw( "(%s)  "ETH_ADDR_FMT"   %d    %#x      "
            "%#x\n",  name, 
            ETH_ADDR_ARGS(port->hw_addr), ntohl(port->speed),
            ntohl(port->flags), ntohl(port->features));
}

/* Pretty-print the struct ofp_switch_features of 'len' bytes at 'oh' to
 * 'string' at the given 'verbosity' level. */
static void
ofp_printw_switch_features(struct ds *string, const void *oh, size_t len,
                          int verbosity)
{
    const struct ofp_switch_features *osf = oh;
    struct ofp_phy_port port_list[OFPP_MAX];
    int n_ports;
    int i;
    
    printw( "dp id:%"PRIx64"\n", ntohll(osf->datapath_id));
    printw( "tables: exact:%d, compressed:%d, general:%d\n",
           ntohl(osf->n_exact), 
           ntohl(osf->n_compression), ntohl(osf->n_general));
    printw( "buffers: size:%d, number:%d\n",
           ntohl(osf->buffer_mb), ntohl(osf->n_buffers));
    printw( "features: capabilities:%#x, actions:%#x\n",
           ntohl(osf->capabilities), ntohl(osf->actions));
    
    if (ntohs(osf->header.length) >= sizeof *osf) {
        len = MIN(len, ntohs(osf->header.length));
    }
    n_ports = (len - sizeof *osf) / sizeof *osf->ports;
    
    memcpy(port_list, osf->ports, (len - sizeof *osf));
    qsort(port_list, n_ports, sizeof port_list[0], compare_portsw);
    mvprintw(1, 0, "      SWITCH FEATURES \n");
    mvprintw(1, COLS/2, " Port No.         addr         speed   flags  features");
    mvchgat(1, 0, -1, A_UNDERLINE, 3, NULL);        
    
    for (i = 0; i < n_ports; i++) {
      move(2+i, COLS/2);
      ofp_printw_phy_port(string, &port_list[i]);
    }
    move(i+3, 0);
}

/* Pretty-print the struct ofp_switch_config of 'len' bytes at 'oh' to 'string'
 * at the given 'verbosity' level. */
static void
ofp_printw_switch_config(struct ds *string, const void *oh, size_t len,
                        int verbosity)
{
    const struct ofp_switch_config *osc = oh;
    uint16_t flags;
    int y, x;
    getyx(stdscr, y, x);
    mvprintw(y-1, 0, "      SWITCH CONFIGURATION \n");
    mvchgat(y-1, 0, -1, A_UNDERLINE, 3, NULL);        
    move(y, x); // move back
    flags = ntohs(osc->flags);
    if (flags & OFPC_SEND_FLOW_EXP) {
        flags &= ~OFPC_SEND_FLOW_EXP;
        printw( " (sending flow expirations)");
    }
    if (flags) {
      printw( " ***unknown flags %04"PRIx16"***", flags);
    }

    printw( " miss_send_len=%"PRIu16"\n\n\n", ntohs(osc->miss_send_len));
}

//static void printw_wild(int y, int x, const char *leader, int is_wild,
//            const char *format, ...) __attribute__((format(printf, 4, 5)));

static void printw_wild(int y, int x, const char *leader, int is_wild,
                       const char *format, ...) 
{
  printw("%s", leader);
    if (!is_wild) {
        va_list args;

        va_start(args, format);
        move(y, x);
        vwprintw(stdscr, format, args);
        va_end(args);
    } else {
      mvprintw(y, x, "?");
    }
}

// Pretty-print the ofp_match structure 
static void ofp_printw_match(struct ds *f, const struct ofp_match *om)
{
    uint16_t w = ntohs(om->wildcards);
    int y, x;
    getyx(stdscr, y, x);

    printw_wild(y, 25, "", w & OFPFW_IN_PORT, "%d", ntohs(om->in_port));
    printw_wild(y, 30, "", w & OFPFW_DL_VLAN, "%04x", ntohs(om->dl_vlan));
    printw_wild(y, 37, "", w & OFPFW_DL_SRC,
               ETH_ADDR_FMT, ETH_ADDR_ARGS(om->dl_src));
    printw_wild(y+1, 37, "", w & OFPFW_DL_DST,
               ETH_ADDR_FMT, ETH_ADDR_ARGS(om->dl_dst));
    printw_wild(y, 57, "", w & OFPFW_DL_TYPE, "%04x", ntohs(om->dl_type));
    printw_wild(y, 64, "", w & OFPFW_NW_SRC, IP_FMT, IP_ARGS(&om->nw_src));
    printw_wild(y+1, 64, "", w & OFPFW_NW_DST, IP_FMT, IP_ARGS(&om->nw_dst));
    printw_wild(y, 81, "", w & OFPFW_NW_PROTO, "%u", om->nw_proto);
    printw_wild(y, 89, "", w & OFPFW_TP_SRC, "%d", ntohs(om->tp_src));
    printw_wild(y+1, 89, "", w & OFPFW_TP_DST, "%d", ntohs(om->tp_dst));
    move(y, x);
    //printw("]");
}

/*
// Pretty-print the OFPT_FLOW_MOD packet of 'len' bytes at 'oh' to 'string'
// at the given 'verbosity' level. 
static void
ofp_print_flow_mod(struct ds *string, const void *oh, size_t len, 
                   int verbosity)
{
    const struct ofp_flow_mod *ofm = oh;

    ofp_print_match(string, &ofm->match);
    ds_put_format(string, " cmd:%d idle:%d pri:%d buf:%#x\n", 
            ntohs(ofm->command), ntohs(ofm->max_idle), 
            ofm->match.wildcards ? ntohs(ofm->priority) : (uint16_t)-1,
            ntohl(ofm->buffer_id));
}

// Pretty-print the OFPT_FLOW_EXPIRED packet of 'len' bytes at 'oh' to 'string'
// at the given 'verbosity' level. 
static void
ofp_print_flow_expired(struct ds *string, const void *oh, size_t len, 
                       int verbosity)
{
    const struct ofp_flow_expired *ofe = oh;

    ofp_print_match(string, &ofe->match);
    ds_put_format(string, 
         " pri%"PRIu16" secs%"PRIu32" pkts%"PRIu64" bytes%"PRIu64"\n", 
         ofe->match.wildcards ? ntohs(ofe->priority) : (uint16_t)-1,
         ntohl(ofe->duration), ntohll(ofe->packet_count), 
         ntohll(ofe->byte_count));
}

// Pretty-print the OFPT_ERROR_MSG packet of 'len' bytes at 'oh' to 'string'
// at the given 'verbosity' level. 
static void
ofp_print_error_msg(struct ds *string, const void *oh, size_t len, 
                       int verbosity)
{
    const struct ofp_error_msg *oem = oh;

    ds_put_format(string, 
         " type%d code%d\n", ntohs(oem->type), ntohs(oem->code));
}

// Pretty-print the OFPT_PORT_STATUS packet of 'len' bytes at 'oh' to 'string'
// at the given 'verbosity' level. 
static void
ofp_print_port_status(struct ds *string, const void *oh, size_t len, 
                      int verbosity)
{
    const struct ofp_port_status *ops = oh;

    if (ops->reason == OFPPR_ADD) {
        ds_put_format(string, "add:");
    } else if (ops->reason == OFPPR_DELETE) {
        ds_put_format(string, "del:");
    } else if (ops->reason == OFPPR_MOD) {
        ds_put_format(string, "mod:");
    } else {
        ds_put_format(string, "err:");
    }

    ofp_print_phy_port(string, &ops->desc);
}
*/

static void
ofp_flow_stats_requestw(struct ds *string, const void *oh, size_t len,
                      int verbosity) 
{
    const struct ofp_flow_stats_request *fsr = oh;

    if (fsr->table_id == 0xff) {
        ds_put_format(string, " table_id=any, ");
    } else {
        ds_put_format(string, " table_id=%"PRIu8", ", fsr->table_id);
    }

    ofp_printw_match(string, &fsr->match);
}

void warn_mesg(int y, int x, const char* message, ...)
{
  va_list args;
  
  attron(COLOR_PAIR(2));
  va_start(args, message);
  move(y,x);
  vwprintw(stdscr, message, args);
  va_end(args);
  attroff(COLOR_PAIR(2));
}

static void
ofp_flow_stats_replyw(struct ds *string, const void *body_, size_t len,
                     int verbosity)
{
    const char *body = body_;
    const char *pos = body;
    int i, y, x;
    attron(COLOR_PAIR(5));
    printw("\nAlv/MI  tid/pr  #pk/by  inp   vlan   ");
    printw("  mac (src/dest)    type   ip (src/dest)   prtcl  tprt(s/d)  actions\n"); 
    attroff(COLOR_PAIR(5));

    for (i = 0; ; i++) {
        const struct ofp_flow_stats *fs;
        ptrdiff_t bytes_left = body + len - pos;
        size_t length;
        //move(LINES-2, 1);
        getyx(stdscr, y, x);
        
        if (bytes_left < sizeof *fs) {
            if (bytes_left != 0) {
              warn_mesg(y+1, COLS/2, " ***%td leftover bytes at end***\n",
                              bytes_left);
            }
            break;
        }

        fs = (const void *) pos;
        length = ntohs(fs->length);
        if (length < sizeof *fs) {
                          warn_mesg(y+1, COLS/2,
                          " ***length=%zu shorter than minimum %zu***\n",
                          length, sizeof *fs);
            break;
        } else if (length > bytes_left) {
                          warn_mesg(y+1, COLS/2,
                          " ***length=%zu but only %td bytes left***\n",
                          length, bytes_left);
            break;
        } else if ((length - sizeof *fs) % sizeof fs->actions[0]) {
                          warn_mesg(y+1, COLS/2,
                          " ***length=%zu has %zu bytes leftover in "
                          "final action***\n",
                          length,
                          (length - sizeof *fs) % sizeof fs->actions[0]);
            break;
        } else if (y >= LINES-2) {
                          warn_mesg(y+1, 10,
                          "*** Not enough space to display more stats: \
            Try a more restrictive flow match ***");
            break;
        }
                    
        if(i%2 == 0)  attron(COLOR_PAIR(1) | A_BOLD);
        else {
          getyx(stdscr, y, x);
          //printw("new color\n");
          mvchgat(y, 0, -1, A_BOLD, 6, NULL);
          mvchgat(y+1 , 0, -1, A_BOLD, 6, NULL);
        }
        mvprintw(y, 1, "%"PRIu32"s", ntohl(fs->duration));
        mvprintw(y, 8, "%"PRIu8"", fs->table_id);
        mvprintw(y, 16, "%"PRIu64"", ntohll(fs->packet_count));

        mvprintw(y+1, 1, "%"PRIu16"s", ntohs(fs->max_idle));
        mvprintw(y+1, 8, "%"PRIu16"", 
                    fs->match.wildcards ? ntohs(fs->priority) : (uint16_t)-1);
        mvprintw(y+1, 16, "%"PRIu64"", ntohll(fs->byte_count));
        move(y, x);
        ofp_printw_match(string, &fs->match);
        ofp_printw_actions(string, fs->actions, length - sizeof *fs);
        move(y+3,1);
        
        pos += length;
     }
}


static void
ofp_aggregate_stats_request(struct ds *string, const void *oh, size_t len,
                            int verbosity) 
{
    const struct ofp_aggregate_stats_request *asr = oh;

    if (asr->table_id == 0xff) {
        ds_put_format(string, " table_id=any, ");
    } else {
        ds_put_format(string, " table_id=%"PRIu8", ", asr->table_id);
    }

    ofp_printw_match(string, &asr->match);
}

static void
ofp_aggregate_stats_reply(struct ds *string, const void *body_, size_t len,
                          int verbosity)
{
    const struct ofp_aggregate_stats_reply *asr = body_;
    int y, x;
    printw( "\n packet_count = %"PRIu64, ntohll(asr->packet_count));
    printw( "\n byte_count   = %"PRIu64, ntohll(asr->byte_count));
    printw( "\n flow_count   = %"PRIu32, ntohl(asr->flow_count));
    getyx(stdscr, y, x);
    move(y-3, 42);
}

static void
ofp_port_stats_reply(struct ds *string, const void *body, size_t len,
                     int verbosity)
{
    const struct ofp_port_stats *ps = body;
    size_t n = len / sizeof *ps;
    int i, y, x;
    getyx(stdscr, y, x);
    mvprintw(y+1, 42, "%zu ports   rx    tx    dropped\n", n);
    mvchgat(y+1, 42, -1, A_BOLD, 5, NULL);
    if (verbosity < 1) {
        return;
    }
    //move(y+2, 43);
    for ( i=2; n--; ps++) {
      mvprintw(y+i, 45, "%"PRIu16": ", ntohs(ps->port_no));
      mvprintw(y+i, 51, "%"PRIu64"", ntohll(ps->rx_count));
      mvprintw(y+i, 57, "%"PRIu64"", ntohll(ps->tx_count));
      mvprintw(y+i, 65, "%"PRIu64"", ntohll(ps->drop_count));
      i++;
    }
    move(y, 84);
    LAST_PY= y+i;
}

static void
ofp_table_stats_reply(struct ds *string, const void *body, size_t len,
                     int verbosity)
{
    const struct ofp_table_stats *ts = body;
    size_t n = len / sizeof *ts;
    int i, y, x;
    getyx(stdscr, y, x);
    mvprintw(y+1, 84, "%zu tables  name    max   active  matched\n", n);
    mvchgat(y+1, 84, -1, A_BOLD, 5, NULL);
    if (verbosity < 1) {
        return;
    }

    for ( i= 2; n--; ts++) {
        char name[OFP_MAX_TABLE_NAME_LEN + 1];
        strncpy(name, ts->name, sizeof name);
        name[OFP_MAX_TABLE_NAME_LEN] = '\0';

        mvprintw(y+i, 89,  "%"PRIu8": ", ts->table_id);
        mvprintw(y+i, 93, "%-8s", name);
        mvprintw(y+i, 101, "%6"PRIu32"", ntohl(ts->max_entries));
        mvprintw(y+i, 107, "%6"PRIu32"", ntohl(ts->active_count));
        mvprintw(y+i, 113, "%6"PRIu64"",  ntohll(ts->matched_count));
        i++;
     }
    if (y+i > LAST_PY) move(y+i+2, 0);
    else move(LAST_PY+2, 0);
} 

enum stats_directionw {
    REQUEST,
    REPLY
};


static void
printw_stats(struct ds *string, int type, const void *body, size_t body_len,
            int verbosity, enum stats_directionw direction)
{
    struct stats_msg {
        size_t min_body, max_body;
        void (*printer)(struct ds *, const void *, size_t len, int verbosity);
    };

    struct stats_type {
        const char *name;
        int dsply_x;
        struct stats_msg request;
        struct stats_msg reply;
    };

    static const struct stats_type stats_types[] = {
        [OFPST_FLOW] = {
          "FLOW STATISTICS", 6,
            { sizeof(struct ofp_flow_stats_request),
              sizeof(struct ofp_flow_stats_request),
             ofp_flow_stats_requestw },
            { 0, SIZE_MAX, ofp_flow_stats_replyw },
        },
        [OFPST_AGGREGATE] = {
          "AGGREGATE FLOW STATISTICS", 6,
             { sizeof(struct ofp_aggregate_stats_request),
             sizeof(struct ofp_aggregate_stats_request),
            ofp_aggregate_stats_request },
          { sizeof(struct ofp_aggregate_stats_reply),
            sizeof(struct ofp_aggregate_stats_reply),
            ofp_aggregate_stats_reply },
        },
        [OFPST_TABLE] = {
          "TABLE STATISTICS", 89,
          { 0, 0, NULL },
          { 0, SIZE_MAX, ofp_table_stats_reply },
        },
        [OFPST_PORT] = {
          "PORT STATISTICS", 47,
           { 0, 0, NULL, },
           { 0, SIZE_MAX, ofp_port_stats_reply },
        },
    };

    const struct stats_type *s;
    const struct stats_msg *m;
    int y, x;
    getyx(stdscr, y, x);
    
    if (type >= ARRAY_SIZE(stats_types) || !stats_types[type].name) {
      warn_mesg(y+1, COLS/2, " ***unknown type %d***\n", type);
      return;
    }

    s = &stats_types[type];
    
    mvprintw(y-1, s->dsply_x, "%s\n", s->name);
    mvchgat(y-1, 0, -1, A_UNDERLINE, 3, NULL);        
    move(y, x); // move back

    m = direction == REQUEST ? &s->request : &s->reply;
    if (body_len < m->min_body || body_len > m->max_body) {
      warn_mesg(y+1, COLS/2," ***body_len=%zu not in %zu...%zu***\n",
                      body_len, m->min_body, m->max_body);
      return;
    }
    if (m->printer) {
      m->printer(string, body, body_len, verbosity);
    }
}

/*
static void
ofp_stats_requestw(struct ds *string, const void *oh, size_t len, int verbosity)
{
    const struct ofp_stats_request *srq = oh;

    if (srq->flags) {
      printw(" ***unknown flags %04"PRIx16"***",
                      ntohs(srq->flags));
    }

    printw_stats(string, ntohs(srq->type), srq->body,
                len - offsetof(struct ofp_stats_request, body),
                verbosity, REQUEST);
}
*/

static void
ofp_stats_replyw(struct ds *string, const void *oh, size_t len, int verbosity)
{
    const struct ofp_stats_reply *srp = oh;

    printw(" flags=");
    if (!srp->flags) {
      printw("none");
    } else {
        uint16_t flags = ntohs(srp->flags);
        if (flags & OFPSF_REPLY_MORE) {
          printw("[more]");
            flags &= ~OFPSF_REPLY_MORE;
        }
        if (flags) {
          printw("[***unknown%04"PRIx16"***]", flags);
        }
    }

    printw_stats(string, ntohs(srp->type), srp->body,
                len - offsetof(struct ofp_stats_reply, body),
                verbosity, REPLY);
}

struct openflow_packetw {
    const char *name;
    size_t min_size;
    void (*printer)(struct ds *, const void *, size_t len, int verbosity);
};

static const struct openflow_packetw packets[] = {
  //    [OFPT_FEATURES_REQUEST] = {
  //      "features_request",
  //      sizeof (struct ofp_header),
  //      NULL,
  //  },
    [OFPT_FEATURES_REPLY] = {
        "features_reply",
        sizeof (struct ofp_switch_features),
        ofp_printw_switch_features,
    },
    //  [OFPT_GET_CONFIG_REQUEST] = {
    //    "get_config_request",
    //    sizeof (struct ofp_header),
    //    NULL,
    // },
    [OFPT_GET_CONFIG_REPLY] = {
        "get_config_reply",
        sizeof (struct ofp_switch_config),
        ofp_printw_switch_config,
    },
    //  [OFPT_SET_CONFIG] = {
    //    "set_config",
    //    sizeof (struct ofp_switch_config),
    //    ofp_print_switch_config,
    //},
    //[OFPT_PACKET_IN] = {
    //    "packet_in",
    //    offsetof(struct ofp_packet_in, data),
    //    ofp_packet_in,
    // },
    //[OFPT_PACKET_OUT] = {
    //    "packet_out",
    //    sizeof (struct ofp_packet_out),
    //    ofp_packet_out,
    //},
    //[OFPT_FLOW_MOD] = {
    //    "flow_mod",
    //    sizeof (struct ofp_flow_mod),
    //    ofp_print_flow_mod,
    //},
    //[OFPT_FLOW_EXPIRED] = {
    //    "flow_expired",
    //    sizeof (struct ofp_flow_expired),
    //    ofp_print_flow_expired,
    //},
    // [OFPT_PORT_MOD] = {
    //    "port_mod",
    //     sizeof (struct ofp_port_mod),
    //    NULL,
    //},
    //[OFPT_PORT_STATUS] = {
    //    "port_status",
    //    sizeof (struct ofp_port_status),
    //    ofp_print_port_status
    //},
    //[OFPT_ERROR_MSG] = {
    //    "error_msg",
    //    sizeof (struct ofp_error_msg),
    //    ofp_print_error_msg,
    //},
    //[OFPT_STATS_REQUEST] = {
    //    "stats_request",
    //    sizeof (struct ofp_stats_request),
    //    ofp_stats_request,
    //},
    [OFPT_STATS_REPLY] = {
        "stats_reply",
         sizeof (struct ofp_stats_reply),
        ofp_stats_replyw,
     },
};

/* Composes and returns a string representing the OpenFlow packet of 'len'
 * bytes at 'oh' at the given 'verbosity' level.  0 is a minimal amount of
 * verbosity and higher numbers increase verbosity.  The caller is responsible
 * for freeing the string. */
void
ofp_to_stringw(const void *oh_, size_t len, int verbosity)
{
    struct ds string = DS_EMPTY_INITIALIZER;
    const struct ofp_header *oh = oh_;
    const struct openflow_packetw *pkt;
    int y, x; 
    getyx(stdscr, y, x);
    if (len < sizeof(struct ofp_header)) {
      //ds_put_cstr(&string, "OpenFlow packet too short:\n");
      // ds_put_hex_dump(&string, oh, len, 0, true);
      //return ds_cstr(&string);
      warn_mesg(y+1, COLS/2, " ***OpenFlow packet too short***\n");
      return;
    } else if (oh->version != OFP_VERSION) {
      //ds_put_format(&string, "Bad OpenFlow version %"PRIu8":\n", oh->version);
      //ds_put_hex_dump(&string, oh, len, 0, true);
      //return ds_cstr(&string);
      warn_mesg(y+1, COLS/2, " ***Bad OpenFlow version %"PRIu8": ***\n", oh->version);
      return;
    } else if (oh->type >= ARRAY_SIZE(packets) || !packets[oh->type].name) {
      // ds_put_format(&string, "Unknown OpenFlow packet type %"PRIu8":\n",
      //          oh->type);
      //  ds_put_hex_dump(&string, oh, len, 0, true);
      //return ds_cstr(&string);
      warn_mesg(y+1, COLS/2, " ***Unknown OpenFlow packet type %"PRIu8":\n", oh->type);
      return;
    }
    
    pkt = &packets[oh->type];
    getyx(stdscr, y, x);
    if ((y < 7) && (!strcmp(pkt->name, "get_config_reply"))) y=7;// will start on line 7
    mvprintw(y, x, "%s (xid=%"PRIx32"):", pkt->name, oh->xid); 

   
    //ds_put_format(&string,  "%s (xid=%"PRIx32"):", pkt->name, oh->xid);

    if (ntohs(oh->length) > len)
      //ds_put_format(&string, " (***truncated to %zu bytes from %"PRIu16"***)",
      // len, ntohs(oh->length));
      warn_mesg(y+1, COLS/2, " ***truncated to %zu bytes from %"PRIu16"***)\n",len, ntohs(oh->length));
    else if (ntohs(oh->length) < len) {
      // ds_put_format(&string, " (***only uses %"PRIu16" bytes out of %zu***)\n",
      //        ntohs(oh->length), len);
      warn_mesg(y+1, COLS/2, "(***only uses %"PRIu16" bytes out of %zu***)\n", ntohs(oh->length), len);
      len = ntohs(oh->length);
    }

    if (len < pkt->min_size) {
      //ds_put_format(&string, " (***length=%zu < min_size=%zu***)\n",
      //          len, pkt->min_size);
      warn_mesg(y+1, COLS/2, " (***length=%zu < min_size=%zu***)\n", len, pkt->min_size);
    } else if (!pkt->printer) {
        if (len > sizeof *oh) {
          //ds_put_format(&string, " length=%"PRIu16" (decoder not implemented)\n",
          //                ntohs(oh->length)); 
          warn_mesg(y+1, COLS/2, " length=%"PRIu16" (decoder not implemented)\n",ntohs(oh->length));
        }
    } else {
        pkt->printer(&string, oh, len, verbosity);
    }

    if (verbosity >= 3) {
        ds_put_hex_dump(&string, oh, len, 0, true);
    }
/*    if (string.string[string.length - 1] != '\n') {
        ds_put_char(&string, '\n');
    }
 */   //return ds_cstr(&string);

}

/*
static void
//printw_and_free(FILE *stream, char *string) 
printw_and_free(FILE *stream) 
{
  //fputs(string, stream);
  fputs("arrived in  new printing file\n", stream);
  //free(string);
}
*/

/* Pretty-print the OpenFlow packet of 'len' bytes at 'oh' to 'stream' at the
 * given 'verbosity' level.  0 is a minimal amount of verbosity and higher
 * numbers increase verbosity. */
void
ofp_printw(FILE *stream, const void *oh, size_t len, int verbosity)
{
  ofp_to_stringw(oh, len, verbosity);
  //mvprintw( 20, 0, "done in  new printing file\n");
  //  printw_and_free(stream, ofp_to_stringw(oh, len, verbosity));
}

/* Dumps the contents of the Ethernet frame in the 'len' bytes starting at
 * 'data' to 'stream' using tcpdump.  'total_len' specifies the full length of
 * the Ethernet frame (of which 'len' bytes were captured).
 *
 * This starts and kills a tcpdump subprocess so it's quite expensive. */
/*
void
ofp_print_packet(FILE *stream, const void *data, size_t len, size_t total_len)
{
    print_and_free(stream, ofp_packet_to_string(data, len, total_len));
}
*/
