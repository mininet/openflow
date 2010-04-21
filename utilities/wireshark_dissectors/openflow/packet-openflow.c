/**
 * Filename: packet-openflow.c
 * Author:   David Underhill
 * Changelog:
 * dgu 	     2008-Aug-26 created
 * brandonh  2008-Oct-5  updated to 0x95
 * brandonh  2008-Nov-25 updated to 0x96 + bugfixes
 * tyabe     2009-May-20 added vlan_pcp_match
 *
 * Defines a Wireshark 1.0.0+ dissector for the OpenFlow protocol version 0x98.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <glib.h>
#include <epan/emem.h>
#include <epan/packet.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/prefs.h>
#include <epan/ipproto.h>
#include <epan/etypes.h>
#include <epan/addr_resolv.h>
#include <string.h>
#include <arpa/inet.h>
#include <openflow/openflow.h>

/** the version of openflow this dissector was written for */
#define DISSECTOR_OPENFLOW_MIN_VERSION OFP_VERSION
#define DISSECTOR_OPENFLOW_MAX_VERSION OFP_VERSION
#define DISSECTOR_OPENFLOW_VERSION_DRAFT_THRESHOLD OFP_VERSION

/** if 0, padding bytes will not be shown in the dissector */
#define SHOW_PADDING 0

#define PROTO_TAG_OPENFLOW  "OFP"

/* Wireshark ID of the OPENFLOW protocol */
static int proto_openflow = -1;
static dissector_handle_t openflow_handle;
static void dissect_openflow(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* traffic will arrive with TCP port OPENFLOW_DST_TCP_PORT */
#define TCP_PORT_FILTER "tcp.port"
static int global_openflow_proto = OPENFLOW_DST_TCP_PORT;

/* try to find the ethernet dissector to dissect encapsulated Ethernet data */
static dissector_handle_t data_ethernet;

/* AM=Async message, CSM=Control/Switch Message, SM=Symmetric Message */
/** names to bind to various values in the type field */
static const value_string names_ofp_type[] = {
    /* Immutable messages. */
    { OFPT_HELLO,               "Hello (SM)" },
    { OFPT_ERROR,               "Error (SM)" },
    { OFPT_ECHO_REQUEST,        "Echo Request (SM)" },
    { OFPT_ECHO_REPLY,          "Echo Reply (SM)" },
    { OFPT_VENDOR,              "Vendor (SM)" },

    /* Switch configuration messages. */
    { OFPT_FEATURES_REQUEST,    "Features Request (CSM)" },
    { OFPT_FEATURES_REPLY,      "Features Reply (CSM)" },
    { OFPT_GET_CONFIG_REQUEST,  "Get Config Request (CSM)" },
    { OFPT_GET_CONFIG_REPLY,    "Get Config Reply (CSM)" },
    { OFPT_SET_CONFIG,          "Set Config (CSM)" },

    /* Asynchronous messages. */
    { OFPT_PACKET_IN,           "Packet In (AM)" },
    { OFPT_FLOW_REMOVED,        "Flow Removed (AM)" },
    { OFPT_PORT_STATUS,         "Port Status (AM)" },

    /* Controller command messages. */
    { OFPT_PACKET_OUT,          "Packet Out (CSM)" },
    { OFPT_FLOW_MOD,            "Flow Mod (CSM)" },
    { OFPT_PORT_MOD,            "Port Mod (CSM)" },

    /* Statistics messages. */
    { OFPT_STATS_REQUEST,       "Stats Request (CSM)" },
    { OFPT_STATS_REPLY,         "Stats Reply (CSM)" },

    /* Barrier messages. */
    { OFPT_BARRIER_REQUEST,     "Barrier Request (CSM)" },
    { OFPT_BARRIER_REPLY,       "Barrier Reply (CSM)" },

    { OFPT_QUEUE_GET_CONFIG_REQUEST, "Get Queue Config Request (CSM)" },
    { OFPT_QUEUE_GET_CONFIG_REPLY,   "Get Queue Config Reply (CSM)" },

    { 0,                        NULL }
};
#define OFP_TYPE_MAX_VALUE OFPT_QUEUE_GET_CONFIG_REPLY

/** names from ofp_action_type */
static const value_string names_ofp_action_type[] = {
    { OFPAT_OUTPUT,       "Output to switch port" },
    { OFPAT_SET_VLAN_VID, "Set the 802.1q VLAN id." },
    { OFPAT_SET_VLAN_PCP, "Set the 802.1q priority." },
    { OFPAT_STRIP_VLAN,   "Strip the 802.1q header." },
    { OFPAT_SET_DL_SRC,   "Ethernet source address" },
    { OFPAT_SET_DL_DST,   "Ethernet destination address" },
    { OFPAT_SET_NW_SRC,   "IP source address" },
    { OFPAT_SET_NW_DST,   "IP destination address" },
    { OFPAT_SET_NW_TOS,   "Set IP TOS field" },
    { OFPAT_SET_TP_SRC,   "TCP/UDP source port" },
    { OFPAT_SET_TP_DST,   "TCP/UDP destination port"},
    { OFPAT_ENQUEUE,      "Enqueue to port queue" },
    { OFPAT_VENDOR,       "Vendor-defined action"},
    { 0,                  NULL }
};
#define NUM_ACTIONS_FLAGS 12
#define NUM_PORT_CONFIG_FLAGS 7
#define NUM_PORT_STATE_FLAGS 1
#define NUM_PORT_FEATURES_FLAGS 12
#define NUM_WILDCARDS 12
#define NUM_CAPABILITIES_FLAGS 8
#define NUM_FLOW_MOD_FLAGS 3
#define NUM_SF_REPLY_FLAGS 1

/** yes/no for bitfields field */
static const value_string names_choice[] = {
    { 0, "No"  },
    { 1, "Yes" },
    { 0, NULL  }
};

/** wildcard or not for bitfields field */
static const value_string wildcard_choice[] = {
    { 0, "Exact"  },
    { 1, "Wildcard" },
    { 0, NULL  }
};

/** wildcard or not for bitfields field */
static const value_string ts_wildcard_choice[] = {
    { 0, "Exact only"  },
    { 1, "Wildcard allowed" },
    { 0, NULL  }
};

/** names from ofp_flow_mod_command */
static const value_string names_flow_mod_command[] = {
    { OFPFC_ADD,           "New flow" },
    { OFPFC_MODIFY,         "Modify all matching flows" },
    { OFPFC_MODIFY_STRICT,  "Modify entry strictly matching wildcards" },
    { OFPFC_DELETE,        "Delete all matching flows" },
    { OFPFC_DELETE_STRICT, "Delete entry strictly matching wildcards and priority" },
    { 0,                   NULL }
};

/** names of stats_types */
static const value_string names_stats_types[] = {
    { OFPST_DESC,      "Description of this OpenFlow switch" },
    { OFPST_FLOW,      "Individual flow statistics" },
    { OFPST_AGGREGATE, "Aggregate flow statistics" },
    { OFPST_TABLE,     "Flow table statistics" },
    { OFPST_PORT,      "Physical port statistics" },
    { OFPST_QUEUE,     "Queue statistics" },
    { OFPST_VENDOR,    "Vendor extension" },
    { 0, NULL }
};

/** names from ofp_flow_mod_command */
static const value_string names_ofp_port_reason[] = {
    { OFPPR_ADD,    "The port was added" },
    { OFPPR_DELETE, "The port was removed" },
    { OFPPR_MODIFY, "Some attribute of the port has changed" },
    { 0,            NULL }
};

/** names from ofp_packet_in_reason */
static const value_string names_ofp_packet_in_reason[] = {
    { OFPR_NO_MATCH, "No matching flow" },
    { OFPR_ACTION,   "Action explicitly output to controller" },
    { 0,             NULL }
};

/** names from ofp_flow_removed_reason */
static const value_string names_ofp_flow_removed_reason[] = {
    { OFPRR_IDLE_TIMEOUT, "Flow idle time exceeded idle_timeout" },
    { OFPRR_HARD_TIMEOUT, "Time exceeded hard_timeout" },
    { OFPRR_DELETE,       "Evicted by a DELETE flow mod." },
    { 0,                  NULL }
};

/** names from ofp_flow_removed_reason */
static const value_string names_ip_frag[] = {
    { OFPC_FRAG_NORMAL, "No special handling for fragments." },
    { OFPC_FRAG_DROP,   "Drop fragments." },
    { OFPC_FRAG_REASM,  "Reassemble (only if OFPC_IP_REASM set)" },
    { 0,                NULL }
};

/** names from ofp_error_type */
static const value_string names_ofp_error_type_reason[] = {
    { OFPET_HELLO_FAILED,       "Hello protocol failed" },
    { OFPET_BAD_REQUEST,        "Request was not understood" },
    { OFPET_BAD_ACTION,         "Error in action description" },
    { OFPET_FLOW_MOD_FAILED,    "Problem modifying flow entry" },
    { OFPET_PORT_MOD_FAILED,    "Port mod request failed" },
    { OFPET_QUEUE_OP_FAILED,    "Problem during queue operation" },
    { 0,                        NULL }
};

static const value_string names_ofp_packet_queue_property_type[] = {
    { OFPQT_NONE,       "No-op Property" },
    { OFPQT_MIN_RATE,   "Min Rate Queue" },
    { 0,                  NULL }
};


/** Address masks */
static const value_string addr_mask[] = {
    { 0, "/32"  },
    { 1, "/31" },
    { 2, "/30" },
    { 3, "/29" },
    { 4, "/28" },
    { 5, "/27" },
    { 6, "/26" },
    { 7, "/25" },
    { 8, "/24" },
    { 9, "/23" },
    { 10, "/22" },
    { 11, "/21" },
    { 12, "/20" },
    { 13, "/19" },
    { 14, "/18" },
    { 15, "/17" },
    { 16, "/16" },
    { 17, "/15" },
    { 18, "/14" },
    { 19, "/13" },
    { 20, "/12" },
    { 21, "/11" },
    { 22, "/10" },
    { 23, "/9" },
    { 24, "/8" },
    { 25, "/7" },
    { 26, "/6" },
    { 27, "/5" },
    { 28, "/4" },
    { 29, "/3" },
    { 30, "/2" },
    { 31, "/1" },
    { 32, "/0" },
    { 63, "/0" },
    { 0, NULL  }
};

/** Address masks */
static const value_string ts_addr_mask[] = {
    { 0, "Exact only"  },
    { 63, "Wildcard allowed" },
    { 0, NULL  }
};

/** Switch config frag values */
static const value_string sc_frag_choices[] = {
    { 0, "No special fragment handling"  },
    { 1, "Drop fragments" },
    { 2, "Reassemble (only if OFPC_IP_REASM set)" },
    { 0, NULL  }
};


/* Error strings for the various error types */
static const gchar *hello_failed_err_str[] = {"No compatible version",
					      "Permissions error"};

#define N_HELLOFAILED   (sizeof hello_failed_err_str / sizeof hello_failed_err_str[0])

static const gchar *bad_request_err_str[] = {"ofp_header.version not supported",
                                             "ofp_header.type not supported",
                                             "ofp_stats_request.type not supported",
                                             "Vendor not supported (in ofp_vendor or ofp_stats_request or ofp_stats_reply)",
                                             "Vendor subtype not supported",
					     "Permissions error",
                                             "Wrong request length for type",
                                             "Specified buffer has already been used",
                                             "Specified buffer does not exist"};

#define N_BADREQUEST    (sizeof bad_request_err_str / sizeof bad_request_err_str[0])

static const gchar *bad_action_err_str[] = {"Unknown action type",
                                            "Length problem in actions",
                                            "Unknown vendor id specified",
                                            "Unknown action type for vendor id",
                                            "Problem validating output action",
                                            "Bad action argument",
                                            "Permissions error",
                                            "Can't handle this many actions",
                                            "Problem validating output queue"};

#define N_BADACTION     (sizeof bad_action_err_str / sizeof bad_action_err_str[0])

static const gchar *flow_mod_failed_err_str[] = {"Flow not added because of full tables",
						 "Flow not added because of conflicting entry in tables",
						 "Permissions error",
						 "Flow not added because of non-zero idle/hard timeout",
                                                 "Unknown command",
                                                 "Unsupported action list - cannot process in the order specified"};

#define N_FLOWMODFAILED (sizeof flow_mod_failed_err_str / sizeof flow_mod_failed_err_str[0])

static const gchar *port_mod_failed_err_str[] = {"Specified port does not exist",
                                                 "Specified hardware address is wrong"};

#define N_PORTMODFAILED (sizeof port_mod_failed_err_str / sizeof port_mod_failed_err_str[0])

static const gchar *queue_op_failed_err_str[] = {"Parent port does not exist",
                                                 "queue does not exist",
                                                 "Permissions error"};

#define N_QUEUEOPFAILED (sizeof queue_op_failed_err_str / sizeof queue_op_failed_err_str[0])

/* ICMP definitions from wireshark source: epan/dissectors/packet-ip.c */
/* ICMP definitions */

#define ICMP_ECHOREPLY     0
#define ICMP_UNREACH       3
#define ICMP_SOURCEQUENCH  4
#define ICMP_REDIRECT      5
#define ICMP_ECHO          8
#define ICMP_RTRADVERT     9
#define ICMP_RTRSOLICIT   10
#define ICMP_TIMXCEED     11
#define ICMP_PARAMPROB    12
#define ICMP_TSTAMP       13
#define ICMP_TSTAMPREPLY  14
#define ICMP_IREQ         15
#define ICMP_IREQREPLY    16
#define ICMP_MASKREQ      17
#define ICMP_MASKREPLY    18

/* ICMP UNREACHABLE */

#define ICMP_NET_UNREACH        0       /* Network Unreachable */
#define ICMP_HOST_UNREACH       1       /* Host Unreachable */
#define ICMP_PROT_UNREACH       2       /* Protocol Unreachable */
#define ICMP_PORT_UNREACH       3       /* Port Unreachable */
#define ICMP_FRAG_NEEDED        4       /* Fragmentation Needed/DF set */
#define ICMP_SR_FAILED          5       /* Source Route failed */
#define ICMP_NET_UNKNOWN        6
#define ICMP_HOST_UNKNOWN       7
#define ICMP_HOST_ISOLATED      8
#define ICMP_NET_ANO            9
#define ICMP_HOST_ANO           10
#define ICMP_NET_UNR_TOS        11
#define ICMP_HOST_UNR_TOS       12
#define ICMP_PKT_FILTERED       13      /* Packet filtered */
#define ICMP_PREC_VIOLATION     14      /* Precedence violation */
#define ICMP_PREC_CUTOFF        15      /* Precedence cut off */

static const gchar *unreach_str[] = {"Network unreachable",
                                     "Host unreachable",
                                     "Protocol unreachable",
                                     "Port unreachable",
                                     "Fragmentation needed",
                                     "Source route failed",
                                     "Destination network unknown",
                                     "Destination host unknown",
                                     "Source host isolated",
                                     "Network administratively prohibited",
                                     "Host administratively prohibited",
                                     "Network unreachable for TOS",
                                     "Host unreachable for TOS",
                                     "Communication administratively filtered",
                                     "Host precedence violation",
                                     "Precedence cutoff in effect"};

#define	N_UNREACH	(sizeof unreach_str / sizeof unreach_str[0])

static const gchar *redir_str[] = {"Redirect for network",
                                   "Redirect for host",
                                   "Redirect for TOS and network",
                                   "Redirect for TOS and host"};

#define	N_REDIRECT	(sizeof redir_str / sizeof redir_str[0])

static const gchar *ttl_str[] = {"Time to live exceeded in transit",
                                 "Fragment reassembly time exceeded"};

#define	N_TIMXCEED	(sizeof ttl_str / sizeof ttl_str[0])

static const gchar *par_str[] = {"IP header bad", "Required option missing"};

#define	N_PARAMPROB	(sizeof par_str / sizeof par_str[0])


/* ARP definitions from wireshark source: epan/dissectors/packet-arp.c */
/* ARP / RARP structs and definitions */
#ifndef ARPOP_REQUEST
#define ARPOP_REQUEST  1       /* ARP request.  */
#endif
#ifndef ARPOP_REPLY
#define ARPOP_REPLY    2       /* ARP reply.  */
#endif
/* Some OSes have different names, or don't define these at all */
#ifndef ARPOP_RREQUEST
#define ARPOP_RREQUEST 3       /* RARP request.  */
#endif
#ifndef ARPOP_RREPLY
#define ARPOP_RREPLY   4       /* RARP reply.  */
#endif
#ifndef ARPOP_IREQUEST
#define ARPOP_IREQUEST 8       /* Inverse ARP (RFC 1293) request.  */
#endif
#ifndef ARPOP_IREPLY
#define ARPOP_IREPLY   9       /* Inverse ARP reply.  */
#endif
#ifndef ATMARPOP_NAK
#define ATMARPOP_NAK   10      /* ATMARP NAK.  */
#endif

static const value_string names_arp_opcode[] = {
  {ARPOP_REQUEST,  "request" },
  {ARPOP_REPLY,    "reply"   },
  {ARPOP_RREQUEST, "reverse request"},
  {ARPOP_RREPLY,   "reverse reply"  },
  {ARPOP_IREQUEST, "inverse request"},
  {ARPOP_IREPLY,   "inverse reply"  },
  {0,              NULL          } };

/* These variables are used to hold the IDs of our fields; they are
 * set when we call proto_register_field_array() in proto_register_openflow()
 */
static gint ofp                  = -1;
static gint ofp_pad              = -1;
static gint ofp_port             = -1;

/* OpenFlow Header */
static gint ofp_header           = -1;
static gint ofp_header_version   = -1;
static gint ofp_header_type      = -1;
static gint ofp_header_length    = -1;
static gint ofp_header_xid       = -1;
static gint ofp_header_warn_ver  = -1;
static gint ofp_header_warn_type = -1;

/* Common Structures */
static gint ofp_phy_port          = -1;
static gint ofp_phy_port_port_no  = -1;
static gint ofp_phy_port_hw_addr  = -1;
static gint ofp_phy_port_name     = -1;
static gint ofp_phy_port_config_hdr = -1;
static gint ofp_phy_port_config[NUM_PORT_CONFIG_FLAGS];
static gint ofp_phy_port_state_hdr = -1;
// the following array is EVIL!!!!! do not use, or a curse upon your family.
static gint ofp_phy_port_state[NUM_PORT_STATE_FLAGS];
// seriously, don't use this bit.
static gint ofp_phy_port_state_not_evil = -1;
static gint ofp_phy_port_state_stp_state = -1;
static gint ofp_phy_port_curr_hdr = -1;
static gint ofp_phy_port_curr[NUM_PORT_FEATURES_FLAGS];
static gint ofp_phy_port_advertised_hdr = -1;
static gint ofp_phy_port_advertised[NUM_PORT_FEATURES_FLAGS];
static gint ofp_phy_port_supported_hdr = -1;
static gint ofp_phy_port_supported[NUM_PORT_FEATURES_FLAGS];
static gint ofp_phy_port_peer_hdr = -1;
static gint ofp_phy_port_peer[NUM_PORT_FEATURES_FLAGS];

static gint ofp_match           = -1;
static gint ofp_match_wildcards_hdr = -1;
static gint ofp_match_wildcards[NUM_WILDCARDS];
static gint ofp_match_in_port   = -1;
static gint ofp_match_dl_src    = -1;
static gint ofp_match_dl_dst    = -1;
static gint ofp_match_dl_vlan   = -1;
static gint ofp_match_dl_vlan_pcp = -1;
static gint ofp_match_dl_type   = -1;
static gint ofp_match_nw_src    = -1;
static gint ofp_match_nw_dst    = -1;
static gint ofp_match_nw_tos    = -1;
static gint ofp_match_nw_proto  = -1;
static gint ofp_match_arp_opcode= -1;
static gint ofp_match_tp_src    = -1;
static gint ofp_match_tp_dst    = -1;
static gint ofp_match_icmp_type = -1;
static gint ofp_match_icmp_code = -1;
static gint ofp_match_nw_src_mask_bits = -1;
static gint ofp_match_nw_dst_mask_bits = -1;

static gint ofp_action         = -1;
static gint ofp_action_type    = -1;
static gint ofp_action_len     = -1;
static gint ofp_action_vlan_vid = -1;
static gint ofp_action_vlan_pcp = -1;
static gint ofp_action_dl_addr = -1;
static gint ofp_action_nw_addr = -1;
static gint ofp_action_nw_tos  = -1;
static gint ofp_action_tp_port = -1;
static gint ofp_action_vendor  = -1;
static gint ofp_action_unknown = -1;
static gint ofp_action_warn    = -1;
static gint ofp_action_num     = -1;

/* type: ofp_action_output */
static gint ofp_action_output         = -1;
static gint ofp_action_output_port    = -1;
static gint ofp_action_output_max_len = -1;

/* type: ofp_action_enqueue */
static gint ofp_action_enqueue = -1;
static gint ofp_action_enqueue_port_no = -1;
static gint ofp_action_enqueue_queue_id = -1;

/* Controller/Switch Messages */
static gint ofp_switch_features               = -1;
static gint ofp_switch_features_datapath_id   = -1;
static gint ofp_switch_features_n_buffers     = -1;
static gint ofp_switch_features_n_tables      = -1;
static gint ofp_switch_features_capabilities_hdr = -1;
static gint ofp_switch_features_capabilities[NUM_CAPABILITIES_FLAGS];
static gint ofp_switch_features_actions_hdr = -1;
static gint ofp_switch_features_actions[NUM_ACTIONS_FLAGS];
static gint ofp_switch_features_actions_warn = -1;
// are these two necessary?
static gint ofp_switch_features_ports_hdr = -1;
static gint ofp_switch_features_ports_num = -1;
static gint ofp_switch_features_ports_warn = -1;

static gint ofp_switch_config               = -1;
static gint ofp_switch_config_flags_hdr = -1;
static gint ofp_switch_config_flags_ip_frag = -1;
static gint ofp_switch_config_miss_send_len = -1;

static gint ofp_queue_get_config_request  = -1;
static gint ofp_queue_get_config_request_port_no = -1;

// there is no limit at the no of queues/port. 1024 is safe for now.
static gint ofp_queue_get_config_reply = -1;
static gint ofp_queue_get_config_reply_port_no = -1;
static gint ofp_queue_get_config_reply_queues_hdr = -1;
static gint ofp_queue_get_config_reply_queues_num = -1;

static gint ofp_packet_queue = -1;
static gint ofp_packet_queue_queue_id = -1;
static gint ofp_packet_queue_len = -1;
static gint ofp_packet_queue_warn = -1;

static gint ofp_packet_queue_property = -1;
static gint ofp_packet_queue_property_len  = -1;
static gint ofp_packet_queue_property_type = -1;
static gint ofp_packet_queue_property_rate = -1;
static gint ofp_packet_queue_properties_hdr = -1;
static gint ofp_packet_queue_properties_num = -1;
static gint ofp_packet_queue_property_unknown = -1;
static gint ofp_packet_queue_property_warn = -1;

static gint ofp_flow_mod              = -1;
/* field: ofp_match */
static gint ofp_flow_mod_cookie       = -1;
static gint ofp_flow_mod_command      = -1;
static gint ofp_flow_mod_idle_timeout = -1;
static gint ofp_flow_mod_hard_timeout = -1;
static gint ofp_flow_mod_priority     = -1;
static gint ofp_flow_mod_buffer_id    = -1;
static gint ofp_flow_mod_out_port     = -1;
static gint ofp_flow_mod_flags[NUM_FLOW_MOD_FLAGS];

static gint ofp_port_mod      = -1;
static gint ofp_port_mod_port_no = -1;
static gint ofp_port_mod_hw_addr = -1;
static gint ofp_port_mod_config_hdr = -1;
static gint ofp_port_mod_config[NUM_PORT_CONFIG_FLAGS];
static gint ofp_port_mod_mask_hdr = -1;
static gint ofp_port_mod_mask[NUM_PORT_CONFIG_FLAGS];
static gint ofp_port_mod_advertise_hdr = -1;
static gint ofp_port_mod_advertise[NUM_PORT_FEATURES_FLAGS];

static gint ofp_stats_request       = -1;
static gint ofp_stats_request_type  = -1;
static gint ofp_stats_request_flags = -1;
static gint ofp_stats_request_body  = -1;

static gint ofp_stats_reply       = -1;
static gint ofp_stats_reply_type  = -1;
static gint ofp_stats_reply_flags = -1;
static gint ofp_stats_reply_flag[NUM_SF_REPLY_FLAGS];
static gint ofp_stats_reply_body  = -1;

static gint ofp_desc_stats = -1;
static gint ofp_desc_stats_mfr_desc = -1;
static gint ofp_desc_stats_hw_desc = -1;
static gint ofp_desc_stats_sw_desc = -1;
static gint ofp_desc_stats_dp_desc = -1;
static gint ofp_desc_stats_serial_num = -1;

static gint ofp_flow_stats_request          = -1;
/* field: ofp_match */
static gint ofp_flow_stats_request_table_id = -1;
static gint ofp_flow_stats_request_out_port = -1;

static gint ofp_flow_stats_reply              = -1;
/* length won't be put in the tree */
static gint ofp_flow_stats_reply_table_id     = -1;
/* field: ofp_match */
static gint ofp_flow_stats_reply_duration_sec = -1;
static gint ofp_flow_stats_reply_duration_nsec  = -1;
static gint ofp_flow_stats_reply_cookie       = -1;
static gint ofp_flow_stats_reply_priority     = -1;
static gint ofp_flow_stats_reply_idle_timeout = -1;
static gint ofp_flow_stats_reply_hard_timeout = -1;
static gint ofp_flow_stats_reply_packet_count = -1;
static gint ofp_flow_stats_reply_byte_count   = -1;
/* field: ofp_actions */

static gint ofp_aggr_stats_request          = -1;
/* field: ofp_match */
static gint ofp_aggr_stats_request_table_id = -1;

static gint ofp_aggr_stats_reply              = -1;
static gint ofp_aggr_stats_reply_packet_count = -1;
static gint ofp_aggr_stats_reply_byte_count   = -1;
static gint ofp_aggr_stats_reply_flow_count   = -1;

static gint ofp_table_stats               = -1;
static gint ofp_table_stats_table_id      = -1;
static gint ofp_table_stats_name          = -1;
static gint ofp_table_stats_wildcards_hdr     = -1;
static gint ofp_table_stats_wildcards[NUM_WILDCARDS];
static gint ofp_table_stats_max_entries   = -1;
static gint ofp_table_stats_active_count  = -1;
static gint ofp_table_stats_lookup_count  = -1;
static gint ofp_table_stats_matched_count = -1;

static gint ofp_port_stats_request = -1;
static gint ofp_port_stats_request_port_no = -1;
static gint ofp_port_stats            = -1;
static gint ofp_port_stats_port_no    = -1;
static gint ofp_port_stats_rx_packets   = -1;
static gint ofp_port_stats_tx_packets  = -1;
static gint ofp_port_stats_rx_bytes   = -1;
static gint ofp_port_stats_tx_bytes  = -1;
static gint ofp_port_stats_rx_dropped   = -1;
static gint ofp_port_stats_tx_dropped  = -1;
static gint ofp_port_stats_rx_errors   = -1;
static gint ofp_port_stats_tx_errors  = -1;
static gint ofp_port_stats_rx_frame_err = -1;
static gint ofp_port_stats_rx_over_err  = -1;
static gint ofp_port_stats_rx_crc_err   = -1;
static gint ofp_port_stats_collisions = -1;

static gint ofp_queue_stats_request          = -1;

static gint ofp_queue_stats = -1;
static gint ofp_queue_stats_port_no = -1;
static gint ofp_queue_stats_queue_id = -1;
static gint ofp_queue_stats_tx_bytes = -1;
static gint ofp_queue_stats_tx_packets = -1;
static gint ofp_queue_stats_tx_errors = -1;

static gint ofp_vendor_stats = -1;
static gint ofp_vendor_stats_vendor = -1;
static gint ofp_vendor_stats_body = -1;

static gint ofp_packet_out           = -1;
static gint ofp_packet_out_buffer_id = -1;
static gint ofp_packet_out_in_port   = -1;
static gint ofp_packet_out_actions_len = -1;
static gint ofp_packet_out_actions_hdr = -1;
static gint ofp_packet_out_data_hdr = -1;

/* Asynchronous Messages */
static gint ofp_packet_in        = -1;
static gint ofp_packet_in_buffer_id = -1;
static gint ofp_packet_in_total_len = -1;
static gint ofp_packet_in_in_port   = -1;
static gint ofp_packet_in_reason = -1;
static gint ofp_packet_in_data_hdr  = -1;

static gint ofp_flow_removed              = -1;
/* field: ofp_match */
static gint ofp_flow_removed_cookie       = -1;
static gint ofp_flow_removed_priority     = -1;
static gint ofp_flow_removed_reason       = -1;
static gint ofp_flow_removed_duration_sec = -1;
static gint ofp_flow_removed_duration_nsec  = -1;
static gint ofp_flow_removed_idle_timeout = -1;
static gint ofp_flow_removed_packet_count = -1;
static gint ofp_flow_removed_byte_count   = -1;

static gint ofp_port_status        = -1;
static gint ofp_port_status_reason = -1;
/* field: ofp_phy_port desc */

static gint ofp_error_msg          = -1;
static gint ofp_error_msg_type     = -1;
static gint ofp_error_msg_code     = -1;
static gint ofp_error_msg_data     = -1;
static gint ofp_error_msg_data_str = -1;

static gint ofp_echo = -1;
static gint ofp_vendor = -1;

/* These are the ids of the subtrees that we may be creating */
static gint ett_ofp = -1;

/* Open Flow Header */
static gint ett_ofp_header = -1;

/* Common Structures */
static gint ett_ofp_phy_port = -1;
static gint ett_ofp_phy_port_config_hdr = -1;
static gint ett_ofp_phy_port_state_hdr = -1;
static gint ett_ofp_phy_port_curr_hdr = -1;
static gint ett_ofp_phy_port_advertised_hdr = -1;
static gint ett_ofp_phy_port_supported_hdr = -1;
static gint ett_ofp_phy_port_peer_hdr = -1;
static gint ett_ofp_match = -1;
static gint ett_ofp_match_wildcards_hdr = -1;
static gint ett_ofp_action = -1;
static gint ett_ofp_action_output = -1;
static gint ett_ofp_action_enqueue = -1;
static gint ett_ofp_packet_queue_root = -1;
static gint ett_ofp_packet_queue = -1;
static gint ett_ofp_packet_queue_property = -1;
static gint ett_ofp_packet_queue_properties_hdr = -1;

/* Controller/Switch Messages */
static gint ett_ofp_switch_features = -1;
static gint ett_ofp_switch_features_capabilities_hdr = -1;
static gint ett_ofp_switch_features_actions_hdr = -1;
static gint ett_ofp_switch_features_ports_hdr = -1;
static gint ett_ofp_switch_config = -1;
static gint ett_ofp_switch_config_flags_hdr = -1;
static gint ett_ofp_flow_mod = -1;
static gint ett_ofp_flow_mod_flags_hdr = -1;
static gint ett_ofp_port_mod = -1;
static gint ett_ofp_port_mod_config_hdr = -1;
static gint ett_ofp_port_mod_mask_hdr = -1;
static gint ett_ofp_port_mod_advertise_hdr = -1;

static gint ett_ofp_queue_get_config_request = -1;
static gint ett_ofp_queue_get_config_reply = -1;
static gint ett_ofp_queue_get_config_reply_queues_hdr = -1;

static gint ett_ofp_stats_request = -1;
static gint ett_ofp_stats_reply = -1;
static gint ett_ofp_stats_reply_flags = -1;
static gint ett_ofp_desc_stats = -1;
static gint ett_ofp_flow_stats_request = -1;
static gint ett_ofp_flow_stats_reply = -1;
static gint ett_ofp_aggr_stats_request = -1;
static gint ett_ofp_aggr_stats_reply = -1;
static gint ett_ofp_table_stats = -1;
static gint ett_ofp_port_stats_request = -1;
static gint ett_ofp_queue_stats_request = -1;
static gint ett_ofp_port_stats = -1;
static gint ett_ofp_queue_stats = -1;
static gint ett_ofp_vendor_stats = -1;
static gint ett_ofp_packet_out = -1;
static gint ett_ofp_packet_out_actions_hdr = -1;
static gint ett_ofp_packet_out_data_hdr  = -1;

/* Asynchronous Messages */
static gint ett_ofp_packet_in = -1;
static gint ett_ofp_packet_in_data_hdr = -1;
static gint ett_ofp_flow_removed = -1;
static gint ett_ofp_port_status = -1;
static gint ett_ofp_error_msg = -1;
static gint ett_ofp_error_msg_data = -1;

void proto_reg_handoff_openflow()
{
    openflow_handle = create_dissector_handle(dissect_openflow, proto_openflow);
    dissector_add(TCP_PORT_FILTER, global_openflow_proto, openflow_handle);
}

#define NO_STRINGS NULL
#define NO_MASK 0x0

/** Returns newly allocated string with two spaces in front of str. */
static inline char* indent( char* str ) {
    char* ret = malloc( strlen(str) + 3 );
    ret[0] = ' ';
    ret[1] = ' ';
    memcpy( &ret[2], str, strlen(str) + 1 );
    return ret;
}

void proto_register_openflow()
{
    data_ethernet = find_dissector("eth");

    /* initialize uninitialized header fields */
    int i;
    for( i=0; i<NUM_CAPABILITIES_FLAGS; i++ ) {
        ofp_switch_features_capabilities[i] = -1;
    }
    for( i=0; i<NUM_ACTIONS_FLAGS; i++ ) {
        ofp_switch_features_actions[i] = -1;
    }
    for( i=0; i<NUM_PORT_CONFIG_FLAGS; i++ ) {
        ofp_phy_port_config[i] = -1;
        ofp_port_mod_config[i] = -1;
        ofp_port_mod_mask[i] = -1;
    }
    for( i=0; i<NUM_PORT_STATE_FLAGS; i++ ) {
        ofp_phy_port_state[i] = -1;
    }
    for( i=0; i<NUM_PORT_FEATURES_FLAGS; i++ ) {
        ofp_phy_port_curr[i] = -1;
        ofp_phy_port_advertised[i] = -1;
        ofp_phy_port_supported[i] = -1;
        ofp_phy_port_peer[i] = -1;
        ofp_port_mod_advertise[i] = -1;
    }
    for( i=0; i<NUM_WILDCARDS; i++ ) {
        ofp_match_wildcards[i] = -1;
        ofp_table_stats_wildcards[i] = -1;
    }
    for (i=0; i<NUM_FLOW_MOD_FLAGS; i++) {
         ofp_flow_mod_flags[i] = -1;
    }
    for( i=0; i<NUM_SF_REPLY_FLAGS; i++ ) {
        ofp_stats_reply_flag[i] = -1;
    }

    /* A header field is something you can search/filter on.
    *
    * We create a structure to register our fields. It consists of an
    * array of register_info structures, each of which are of the format
    * {&(field id), {name, abbrev, type, display, strings, bitmask, blurb, HFILL}}.
    */
    static hf_register_info hf[] = {
        /* header fields */
        { &ofp,
          { "Data", "of.data", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "OpenFlow PDU", HFILL }},

        { &ofp_pad,
          { "Pad", "of.pad", FT_UINT8, BASE_DEC, NO_STRINGS, NO_MASK, "Pad", HFILL }},

        { &ofp_header,
          { "Header", "of.header", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "OpenFlow Header", HFILL }},

        { &ofp_header_version,
          { "Version", "of.ver", FT_UINT8, BASE_HEX, NO_STRINGS, NO_MASK, "Version", HFILL }},

        { &ofp_header_type,
          { "Type", "of.type", FT_UINT8, BASE_DEC, VALS(names_ofp_type), NO_MASK, "Type", HFILL }},

        { &ofp_header_length,
          { "Length", "of.len", FT_UINT8, BASE_DEC, NO_STRINGS, NO_MASK, "Length (bytes)", HFILL }},

        { &ofp_header_xid,
          { "Transaction ID", "of.id", FT_UINT32, BASE_DEC, NO_STRINGS, NO_MASK, "Transaction ID", HFILL }},

        { &ofp_header_warn_ver,
          { "Warning", "of.warn_ver", FT_STRING, BASE_NONE, NO_STRINGS, NO_MASK, "Version Warning", HFILL }},

        { &ofp_header_warn_type,
          { "Warning", "of.warn_type", FT_STRING, BASE_NONE, NO_STRINGS, NO_MASK, "Type Warning", HFILL }},

        /* CS: Common Structures */
        { &ofp_port,
          { "Port #", "of.port", FT_UINT16, BASE_DEC, NO_STRINGS, NO_MASK, "Port #", HFILL }}, /* for searching numerically */


        /* CS: Physical Port Information */
        { &ofp_phy_port,
          { "Physical Port", "of.port", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Physical Port", HFILL }},

        { &ofp_phy_port_port_no,
          { "Port #", "of.port_no", FT_STRING, BASE_NONE, NO_STRINGS, NO_MASK, "Port #", HFILL }},

        { &ofp_phy_port_hw_addr,
          { "MAC Address", "of.port_hw_addr", FT_ETHER, BASE_NONE, NO_STRINGS, NO_MASK, "MAC Address", HFILL }},

        { &ofp_phy_port_name,
          { "Port Name", "of.port_port_name", FT_STRING, BASE_NONE, NO_STRINGS, NO_MASK, "Port Name", HFILL }},

        { &ofp_phy_port_config_hdr,
          { "Port Config Flags", "of.port_config", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Config Flags", HFILL }},

        { &ofp_phy_port_config[0],
          { "  Port is administratively down", "of.port_config_port_down", FT_UINT32, BASE_DEC, VALS(names_choice), OFPPC_PORT_DOWN, "Port is administratively down", HFILL }},

        { &ofp_phy_port_config[1],
          { "  Disable 802.1D spanning tree on port", "of.port_config_no_stp", FT_UINT32, BASE_DEC, VALS(names_choice), OFPPC_NO_STP, "Disable 802.1D spanning tree on port", HFILL }},

        { &ofp_phy_port_config[2],
          { "  Drop non-802.1D packets received on port", "of.port_config_no_recv", FT_UINT32, BASE_DEC, VALS(names_choice), OFPPC_NO_RECV, "Drop non-802.1D packets received on port", HFILL }},

        { &ofp_phy_port_config[3],
          { "  Drop received 802.1D STP packets", "of.port_config_no_revc_stp", FT_UINT32, BASE_DEC, VALS(names_choice), OFPPC_NO_RECV_STP, "Drop received 802.1D STP packets", HFILL }},

        { &ofp_phy_port_config[4],
          { "  Do not include this port when flooding", "of.port_config_no_flood", FT_UINT32, BASE_DEC, VALS(names_choice), OFPPC_NO_FLOOD, "Do not include this port when flooding", HFILL }},

        { &ofp_phy_port_config[5],
          { "  Drop packets forwarded to port", "of.port_config_no_fwd", FT_UINT32, BASE_DEC, VALS(names_choice), OFPPC_NO_FWD, "Drop packets forwarded to port", HFILL }},

        { &ofp_phy_port_config[6],
          { "  Do not send packet-in msgs for port", "of.port_config_no_packet_in", FT_UINT32, BASE_DEC, VALS(names_choice), OFPPC_NO_PACKET_IN, "Do not send packet-in msgs for port", HFILL }},

        { &ofp_phy_port_state_hdr,
          { "Port State Flags", "of.port_state", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "State Flags", HFILL }},
/*
 *      { &ofp_phy_port_state[0],
          { "  No physical link present", "of.port_state_link_down", FT_NONE, BASE_NONE, NO_STRINGS, OFPPS_LINK_DOWN, "No physical link present", HFILL }},
*/
        { &ofp_phy_port_state_not_evil,
          { "  No physical link present", "of.port_state_link_down_not_evil", FT_NONE, BASE_NONE, NO_STRINGS, OFPPS_LINK_DOWN, "No physical link present", HFILL }},

        { &ofp_phy_port_state_stp_state,
          { "STP state", "of.port_state_stp_listen", FT_STRING, BASE_NONE, NO_STRINGS, NO_MASK, "STP state", HFILL }},

        { &ofp_phy_port_curr_hdr,
          { "Port Current Flags", "of.port_curr", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Current Flags", HFILL }},
		
        { &ofp_phy_port_curr[0],
	      { "   10 Mb half-duplex rate support", "of.port_curr_10mb_hd" , FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_10MB_HD, "10 Mb half-duplex rate support", HFILL }},
		
	    { &ofp_phy_port_curr[1],
	      { "   10 Mb full-duplex rate support", "of.port_curr_10mb_fd",  FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_10MB_FD, "10 Mb full-duplex rate support", HFILL }},
		
	    { &ofp_phy_port_curr[2],
	      { "  100 Mb half-duplex rate support", "of.port_curr_100mb_hd", FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_100MB_HD, "100 Mb half-duplex rate support", HFILL }},
		
        { &ofp_phy_port_curr[3],
	      { "  100 Mb full-duplex rate support", "of.port_curr_100mb_fd", FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_100MB_FD, "100 Mb full-duplex rate support", HFILL }},
		
	    { &ofp_phy_port_curr[4],
	      { "    1 Gb half-duplex rate support", "of.port_curr_1gb_hd",   FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_1GB_HD, "1 Gb half-duplex rate support", HFILL }},
		
	    { &ofp_phy_port_curr[5],
	      { "    1 Gb full-duplex rate support", "of.port_curr_1gb_fd",   FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_1GB_FD, "1 Gb full-duplex rate support", HFILL }},
		
	    { &ofp_phy_port_curr[6],
          { "   10 Gb full-duplex rate support", "of.port_curr_10gb_hd",  FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_10GB_FD, "10 Gb full-duplex rate support", HFILL }},
		
	    { &ofp_phy_port_curr[7],
		  { "   Copper medium support", "of.port_curr_copper",  FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_COPPER, "Copper medium support", HFILL }},
		
		{ &ofp_phy_port_curr[8],
		  { "   Fiber medium support", "of.port_curr_fiber",  FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_FIBER, "Fiber medium support", HFILL }},
		
		{ &ofp_phy_port_curr[9],
		  { "   Auto-negotiation support", "of.port_curr_autoneg",  FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_AUTONEG, "Auto-negotiation support", HFILL }},
		
        { &ofp_phy_port_curr[10],
		  { "   Pause support", "of.port_curr_pause",  FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_PAUSE, "Pause support", HFILL }},
		
	    { &ofp_phy_port_curr[11],
	      { "   Asymmetric pause support", "of.port_curr_pause_asym",  FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_PAUSE_ASYM, "Asymmetric pause support", HFILL }},

        { &ofp_phy_port_advertised_hdr,
          { "Port Advertsied Flags", "of.port_advertised", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Advertised Flags", HFILL }},

        { &ofp_phy_port_advertised[0],
  	      { "   10 Mb half-duplex rate support", "of.port_advertised_10mb_hd" , FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_10MB_HD, "10 Mb half-duplex rate support", HFILL }},
  		
  	    { &ofp_phy_port_advertised[1],
  	      { "   10 Mb full-duplex rate support", "of.port_advertised_10mb_fd",  FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_10MB_FD, "10 Mb full-duplex rate support", HFILL }},
  		
  	    { &ofp_phy_port_advertised[2],
  	      { "  100 Mb half-duplex rate support", "of.port_advertised_100mb_hd", FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_100MB_HD, "100 Mb half-duplex rate support", HFILL }},
  		
        { &ofp_phy_port_advertised[3],
  	      { "  100 Mb full-duplex rate support", "of.port_advertised_100mb_fd", FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_100MB_FD, "100 Mb full-duplex rate support", HFILL }},
  		
  	    { &ofp_phy_port_advertised[4],
  	      { "    1 Gb half-duplex rate support", "of.port_advertised_1gb_hd",   FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_1GB_HD, "1 Gb half-duplex rate support", HFILL }},
  		
  	    { &ofp_phy_port_advertised[5],
  	      { "    1 Gb full-duplex rate support", "of.port_advertised_1gb_fd",   FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_1GB_FD, "1 Gb full-duplex rate support", HFILL }},
  		
  	    { &ofp_phy_port_advertised[6],
          { "   10 Gb full-duplex rate support", "of.port_advertised_10gb_hd",  FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_10GB_FD, "10 Gb full-duplex rate support", HFILL }},
  		
  	    { &ofp_phy_port_advertised[7],
  		  { "   Copper medium support", "of.port_advertised_copper",  FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_COPPER, "Copper medium support", HFILL }},
  		
  		{ &ofp_phy_port_advertised[8],
  		  { "   Fiber medium support", "of.port_advertised_fiber",  FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_FIBER, "Fiber medium support", HFILL }},
  		
  		{ &ofp_phy_port_advertised[9],
  		  { "   Auto-negotiation support", "of.port_advertised_autoneg",  FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_AUTONEG, "Auto-negotiation support", HFILL }},
  		
        { &ofp_phy_port_advertised[10],
  		  { "   Pause support", "of.port_advertised_pause",  FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_PAUSE, "Pause support", HFILL }},
  		
  	    { &ofp_phy_port_advertised[11],
  	      { "   Asymmetric pause support", "of.port_advertised_pause_asym",  FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_PAUSE_ASYM, "Asymmetric pause support", HFILL }},

        { &ofp_phy_port_supported_hdr,
          { "Port Supported Flags", "of.port_supported", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Supported Flags", HFILL }},

        { &ofp_phy_port_supported[0],
  	      { "   10 Mb half-duplex rate support", "of.port_supported_10mb_hd" , FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_10MB_HD, "10 Mb half-duplex rate support", HFILL }},
  		
  	    { &ofp_phy_port_supported[1],
  	      { "   10 Mb full-duplex rate support", "of.port_supported_10mb_fd",  FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_10MB_FD, "10 Mb full-duplex rate support", HFILL }},
  		
  	    { &ofp_phy_port_supported[2],
  	      { "  100 Mb half-duplex rate support", "of.port_supported_100mb_hd", FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_100MB_HD, "100 Mb half-duplex rate support", HFILL }},
  		
        { &ofp_phy_port_supported[3],
  	      { "  100 Mb full-duplex rate support", "of.port_supported_100mb_fd", FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_100MB_FD, "100 Mb full-duplex rate support", HFILL }},
  		
  	    { &ofp_phy_port_supported[4],
  	      { "    1 Gb half-duplex rate support", "of.port_supported_1gb_hd",   FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_1GB_HD, "1 Gb half-duplex rate support", HFILL }},
  		
  	    { &ofp_phy_port_supported[5],
  	      { "    1 Gb full-duplex rate support", "of.port_supported_1gb_fd",   FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_1GB_FD, "1 Gb full-duplex rate support", HFILL }},
  		
  	    { &ofp_phy_port_supported[6],
            { "   10 Gb full-duplex rate support", "of.port_supported_10gb_hd",  FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_10GB_FD, "10 Gb full-duplex rate support", HFILL }},
  		
  	    { &ofp_phy_port_supported[7],
  		  { "   Copper medium support", "of.port_supported_copper",  FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_COPPER, "Copper medium support", HFILL }},
  		
  		{ &ofp_phy_port_supported[8],
  		  { "   Fiber medium support", "of.port_supported_fiber",  FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_FIBER, "Fiber medium support", HFILL }},
  		
  		{ &ofp_phy_port_supported[9],
  		  { "   Auto-negotiation support", "of.port_supported_autoneg",  FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_AUTONEG, "Auto-negotiation support", HFILL }},
  		
        { &ofp_phy_port_supported[10],
  		  { "   Pause support", "of.port_supported_pause",  FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_PAUSE, "Pause support", HFILL }},
  		
  	    { &ofp_phy_port_supported[11],
  	      { "   Asymmetric pause support", "of.port_supported_pause_asym",  FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_PAUSE_ASYM, "Asymmetric pause support", HFILL }},

        { &ofp_phy_port_peer_hdr,
          { "Port Peer Flags", "of.port_peer", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Peer Flags", HFILL }},

        { &ofp_phy_port_peer[0],
    	  { "   10 Mb half-duplex rate support", "of.port_peer_10mb_hd" , FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_10MB_HD, "10 Mb half-duplex rate support", HFILL }},
    		
        { &ofp_phy_port_peer[1],
    	  { "   10 Mb full-duplex rate support", "of.port_peer_10mb_fd",  FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_10MB_FD, "10 Mb full-duplex rate support", HFILL }},
    		
    	{ &ofp_phy_port_peer[2],
    	  { "  100 Mb half-duplex rate support", "of.port_peer_100mb_hd", FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_100MB_HD, "100 Mb half-duplex rate support", HFILL }},
    		
        { &ofp_phy_port_peer[3],
    	  { "  100 Mb full-duplex rate support", "of.port_peer_100mb_fd", FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_100MB_FD, "100 Mb full-duplex rate support", HFILL }},
    		
    	{ &ofp_phy_port_peer[4],
    	  { "    1 Gb half-duplex rate support", "of.port_peer_1gb_hd",   FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_1GB_HD, "1 Gb half-duplex rate support", HFILL }},

        { &ofp_phy_port_peer[5],
    	  { "    1 Gb full-duplex rate support", "of.port_peer_1gb_fd",   FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_1GB_FD, "1 Gb full-duplex rate support", HFILL }},
    		
    	{ &ofp_phy_port_peer[6],
          { "   10 Gb full-duplex rate support", "of.port_peer_10gb_hd",  FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_10GB_FD, "10 Gb full-duplex rate support", HFILL }},
    		
    	{ &ofp_phy_port_peer[7],
    	  { "   Copper medium support", "of.port_peer_copper",  FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_COPPER, "Copper medium support", HFILL }},
    		
    	{ &ofp_phy_port_peer[8],
    	  { "   Fiber medium support", "of.port_peer_fiber",  FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_FIBER, "Fiber medium support", HFILL }},
    		
    	{ &ofp_phy_port_peer[9],
    	  { "   Auto-negotiation support", "of.port_peer_autoneg",  FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_AUTONEG, "Auto-negotiation support", HFILL }},
    		
        { &ofp_phy_port_peer[10],
    	  { "   Pause support", "of.port_peer_pause",  FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_PAUSE, "Pause support", HFILL }},
    		
        { &ofp_phy_port_peer[11],
    	  { "   Asymmetric pause support", "of.port_peer_pause_asym",  FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_PAUSE_ASYM, "Asymmetric pause support", HFILL }},


        /* CS: match */
        { &ofp_match,
          { "Match", "of.match", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Match", HFILL }},

        { &ofp_match_wildcards_hdr,
          { "Match Types", "of.wildcards", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Match Types (Wildcards)", HFILL }},

        { &ofp_match_wildcards[0],
          { "  Input port", "of.wildcard_in_port" , FT_UINT32, BASE_DEC, VALS(wildcard_choice), OFPFW_IN_PORT, "Input Port", HFILL }},

        { &ofp_match_wildcards[1],
          { "  VLAN ID", "of.wildcard_dl_vlan" , FT_UINT32, BASE_DEC, VALS(wildcard_choice), OFPFW_DL_VLAN, "VLAN ID", HFILL }},

        { &ofp_match_wildcards[2],
          { "  Ethernet Src Addr", "of.wildcard_dl_src" , FT_UINT32, BASE_DEC, VALS(wildcard_choice), OFPFW_DL_SRC, "Ethernet Source Address", HFILL }},

        { &ofp_match_wildcards[3],
          { "  Ethernet Dst Addr", "of.wildcard_dl_dst" , FT_UINT32, BASE_DEC, VALS(wildcard_choice), OFPFW_DL_DST, "Ethernet Destination Address", HFILL }},

        { &ofp_match_wildcards[4],
          { "  Ethernet Type", "of.wildcard_dl_type" , FT_UINT32, BASE_DEC, VALS(wildcard_choice), OFPFW_DL_TYPE, "Ethernet Type", HFILL }},

        { &ofp_match_wildcards[5],
          { "  IP Protocol", "of.wildcard_nw_proto" , FT_UINT32, BASE_DEC, VALS(wildcard_choice), OFPFW_NW_PROTO, "IP Protocol", HFILL }},

        { &ofp_match_wildcards[6],
          { "  TCP/UDP Src Port", "of.wildcard_tp_src" , FT_UINT32, BASE_DEC, VALS(wildcard_choice), OFPFW_TP_SRC, "TCP/UDP Source Port", HFILL }},

        { &ofp_match_wildcards[7],
          { "  TCP/UDP Dst Port", "of.wildcard_tp_dst" , FT_UINT32, BASE_DEC, VALS(wildcard_choice), OFPFW_TP_DST, "TCP/UDP Destinatoin Port", HFILL }},

        { &ofp_match_wildcards[8],
            { "  IP Src Addr Mask", "of.wildcard_nw_src" , FT_UINT32, BASE_DEC, VALS(addr_mask), OFPFW_NW_SRC_MASK, "IP Source Address Mask", HFILL }},

        { &ofp_match_wildcards[9],
            { "  IP Dst Addr Mask", "of.wildcard_nw_dst" , FT_UINT32, BASE_DEC, VALS(addr_mask), OFPFW_NW_DST_MASK , "IP Destination Address Mask", HFILL }},

        { &ofp_match_wildcards[10],
            { "  VLAN priority", "of.wildcard_dl_vlan_pcp" , FT_UINT32, BASE_DEC, VALS(wildcard_choice), OFPFW_DL_VLAN_PCP, "VLAN priority", HFILL }},

        { &ofp_match_wildcards[11],
            { "  IPv4 DSCP", "of.wildcard_nw_tos" , FT_UINT32, BASE_DEC, VALS(wildcard_choice), OFPFW_NW_TOS, "IPv4 DSCP", HFILL }},

        { &ofp_table_stats_wildcards[0],
          { "  Input port", "of.wildcard_in_port" , FT_UINT32, BASE_DEC, VALS(ts_wildcard_choice), OFPFW_IN_PORT, "Input Port", HFILL }},

        { &ofp_table_stats_wildcards[1],
          { "  VLAN ID", "of.wildcard_dl_vlan" , FT_UINT32, BASE_DEC, VALS(ts_wildcard_choice), OFPFW_DL_VLAN, "VLAN ID", HFILL }},

        { &ofp_table_stats_wildcards[2],
          { "  Ethernet Src Addr", "of.wildcard_dl_src" , FT_UINT32, BASE_DEC, VALS(ts_wildcard_choice), OFPFW_DL_SRC, "Ethernet Source Address", HFILL }},

        { &ofp_table_stats_wildcards[3],
          { "  Ethernet Dst Addr", "of.wildcard_dl_dst" , FT_UINT32, BASE_DEC, VALS(ts_wildcard_choice), OFPFW_DL_DST, "Ethernet Destination Address", HFILL }},

        { &ofp_table_stats_wildcards[4],
          { "  Ethernet Type", "of.wildcard_dl_type" , FT_UINT32, BASE_DEC, VALS(ts_wildcard_choice), OFPFW_DL_TYPE, "Ethernet Type", HFILL }},

        { &ofp_table_stats_wildcards[5],
          { "  IP Protocol", "of.wildcard_nw_proto" , FT_UINT32, BASE_DEC, VALS(ts_wildcard_choice), OFPFW_NW_PROTO, "IP Protocol", HFILL }},

        { &ofp_table_stats_wildcards[6],
          { "  TCP/UDP Src Port", "of.wildcard_tp_src" , FT_UINT32, BASE_DEC, VALS(ts_wildcard_choice), OFPFW_TP_SRC, "TCP/UDP Source Port", HFILL }},

        { &ofp_table_stats_wildcards[7],
          { "  TCP/UDP Dst Port", "of.wildcard_tp_dst" , FT_UINT32, BASE_DEC, VALS(ts_wildcard_choice), OFPFW_TP_DST, "TCP/UDP Destinatoin Port", HFILL }},

        { &ofp_table_stats_wildcards[8],
            { "  IP Src Addr Mask", "of.wildcard_nw_src" , FT_UINT32, BASE_DEC, VALS(ts_addr_mask), OFPFW_NW_SRC_MASK, "IP Source Address Mask", HFILL }},

        { &ofp_table_stats_wildcards[9],
            { "  IP Dst Addr Mask", "of.wildcard_nw_dst" , FT_UINT32, BASE_DEC, VALS(ts_addr_mask), OFPFW_NW_DST_MASK , "IP Destination Address Mask", HFILL }},

        { &ofp_table_stats_wildcards[10],
          { "  VLAN priority", "of.wildcard_dl_vlan_pcp" , FT_UINT32, BASE_DEC, VALS(ts_wildcard_choice), OFPFW_DL_VLAN_PCP, "VLAN priority", HFILL }},

        { &ofp_match_in_port,
          { "Input Port", "of.match_in_port", FT_STRING, BASE_NONE, NO_STRINGS, NO_MASK, "Input Port", HFILL }},

        { &ofp_match_dl_src,
          { "Ethernet Src Addr", "of.match_dl_src", FT_ETHER, BASE_NONE, NO_STRINGS, NO_MASK, "Source MAC Address", HFILL }},

        { &ofp_match_dl_dst,
          { "Ethernet Dst Addr", "of.match_dl_dst", FT_ETHER, BASE_NONE, NO_STRINGS, NO_MASK, "Destination MAC Address", HFILL }},

        { &ofp_match_dl_vlan,
          { "Input VLAN ID", "of.match_dl_vlan", FT_UINT16, BASE_DEC, NO_STRINGS, NO_MASK, "Input VLAN ID", HFILL }},

        { &ofp_match_dl_type,
          { "Ethernet Type", "of.match_dl_type", FT_UINT16, BASE_HEX, NO_STRINGS, NO_MASK, "Ethernet Type", HFILL }},

        { &ofp_match_nw_src,
          { "IP Src Addr", "of.match_nw_src", FT_IPv4, BASE_DEC, NO_STRINGS, NO_MASK, "Source IP Address", HFILL }},

        { &ofp_match_nw_dst,
          { "IP Dst Addr", "of.match_nw_dst", FT_IPv4, BASE_DEC, NO_STRINGS, NO_MASK, "Destination IP Address", HFILL }},

        { &ofp_match_nw_proto,
          { "IP Protocol", "of.match_nw_proto", FT_UINT8, BASE_HEX, NO_STRINGS, NO_MASK, "IP Protocol", HFILL }},

        { &ofp_match_arp_opcode,
          { "ARP Opcode", "of.match_nw_proto", FT_UINT8, BASE_DEC, VALS(names_arp_opcode), NO_MASK, "ARP Opcode", HFILL }},

        { &ofp_match_dl_vlan_pcp,
          { "Input VLAN priority", "of.match_dl_vlan_pcp", FT_UINT8, BASE_DEC, NO_STRINGS, NO_MASK, "Input VLAN priority", HFILL }},

        { &ofp_match_nw_tos,
          { "IPv4 DSCP", "of.match_nw_tos", FT_UINT8, BASE_DEC, NO_STRINGS, NO_MASK, "IPv4 DSCP", HFILL }},

        { &ofp_match_tp_src,
          { "TCP/UDP Src Port", "of.match_tp_src", FT_UINT16, BASE_DEC, NO_STRINGS, NO_MASK, "TCP/UDP Source Port", HFILL }},

        { &ofp_match_tp_dst,
          { "TCP/UDP Dst Port", "of.match_tp_dst", FT_UINT16, BASE_DEC, NO_STRINGS, NO_MASK, "TCP/UDP Destination Port", HFILL }},

        { &ofp_match_icmp_type,
          { "ICMP Type", "of.match_tp_src", FT_UINT16, BASE_DEC, NO_STRINGS, NO_MASK, "ICMP Type", HFILL }},

        { &ofp_match_icmp_code,
          { "ICMP Code", "of.match_tp_dst", FT_UINT16, BASE_DEC, NO_STRINGS, NO_MASK, "ICMP Code", HFILL }},

        { &ofp_match_nw_src_mask_bits,
            { "IP Src Addr Mask Bits", "of.match_nw_src_mask_bits", FT_STRING, BASE_NONE, NO_STRINGS, NO_MASK, "Source IP Address Mask Bits", HFILL }},

        { &ofp_match_nw_dst_mask_bits,
            { "IP Dst Addr Mask Bits", "of.match_nw_dst_mask_bits", FT_STRING, BASE_NONE, NO_STRINGS, NO_MASK, "Destination IP Address Mask Bits", HFILL }},

        /* CS: action type */
        { &ofp_action,
          { "Action", "of.action", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Action", HFILL }},

        { &ofp_action_type,
          { "Type", "of.action_type", FT_UINT16, BASE_DEC, VALS(names_ofp_action_type), NO_MASK, "Type", HFILL }},

        { &ofp_action_len,
          { "Len", "of.action_len", FT_UINT16, BASE_DEC, NO_STRINGS, NO_MASK, "Len", HFILL }},

        { &ofp_action_vlan_vid,
          { "VLAN ID", "of.action_vlan_vid", FT_UINT16, BASE_DEC, NO_STRINGS, NO_MASK, "VLAN ID", HFILL }},

        { &ofp_action_vlan_pcp,
          { "VLAN priority", "of.action_vlan_pcp", FT_UINT8, BASE_DEC, NO_STRINGS, NO_MASK, "VLAN priority", HFILL }},

        { &ofp_action_dl_addr,
          { "MAC Addr", "of.action_dl_addr", FT_ETHER, BASE_NONE, NO_STRINGS, NO_MASK, "MAC Addr", HFILL }},

        { &ofp_action_nw_addr,
          { "IP Addr", "of.action_nw_addr", FT_IPv4, BASE_NONE, NO_STRINGS, NO_MASK, "IP Addr", HFILL }},

        { &ofp_action_nw_tos,
          { "IP TOS bits", "of.action_vlan_pcp", FT_UINT8, BASE_DEC, NO_STRINGS, NO_MASK, "IP TOS bits", HFILL }},

        { &ofp_action_tp_port,
          { "Port", "of.action_tp_port", FT_UINT16, BASE_DEC, NO_STRINGS, NO_MASK, "TCP/UDP Port", HFILL }},

        { &ofp_action_vendor,
          { "Vendor-defined", "of.action_vendor", FT_UINT32, BASE_DEC, NO_STRINGS, NO_MASK, "Vendor-defined", HFILL }},

        { &ofp_action_unknown,
          { "Unknown Action Type", "of.action_unknown", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Unknown Action Type", HFILL }},

        { &ofp_action_warn,
          { "Warning", "of.action_warn", FT_STRING, BASE_NONE, NO_STRINGS, NO_MASK, "Warning", HFILL }},

        { &ofp_action_num,
          { "# of Actions", "of.action_num", FT_UINT32, BASE_DEC, NO_STRINGS, NO_MASK, "Number of Actions", HFILL }},

        /* CS: ofp_action_output */
        { &ofp_action_output,
          { "Output Action(s)", "of.action_output", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Output Action(s)", HFILL }},

        { &ofp_action_output_port,
          { "Output port", "of.action_output_port", FT_STRING, BASE_NONE, NO_STRINGS, NO_MASK, "Output port", HFILL }},

        { &ofp_action_output_max_len,
          { "Max Bytes to Send", "of.action_output_max_len", FT_STRING, BASE_NONE, NO_STRINGS, NO_MASK, "Maximum Bytes to Send", HFILL }},

        /* CS: ofp_action_enqueue */
        { &ofp_action_enqueue,
          { "Enqueue Action(s)", "of.action_enqueue", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Enqueue Action", HFILL }},

        { &ofp_action_enqueue_port_no,
          { "Output port", "of.action_enqueue_port", FT_STRING, BASE_NONE, NO_STRINGS, NO_MASK, "Output port", HFILL }},

        { &ofp_action_enqueue_queue_id,
          { "Output Queue", "of.action_enqueue_queue", FT_STRING, BASE_NONE, NO_STRINGS, NO_MASK, "Output queue", HFILL }},

        /* CSM: Features Request */
        /* nothing beyond the header */

        /* CSM: Features Reply */
        { &ofp_switch_features,
          { "Switch Features", "of.sf", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Switch Features", HFILL }},

        { &ofp_switch_features_datapath_id,
          { "Datapath ID", "of.sf_datapath_id", FT_UINT64, BASE_HEX, NO_STRINGS, NO_MASK, "Datapath ID", HFILL }},

        { &ofp_switch_features_n_buffers,
          { "Max packets buffered", "of.sf_n_buffers", FT_UINT32, BASE_DEC, NO_STRINGS, NO_MASK, "Max packets buffered", HFILL }},

        { &ofp_switch_features_n_tables,
          { "Number of Tables", "of.sf_n_tables", FT_UINT8, BASE_DEC, NO_STRINGS, NO_MASK, "Number of tables", HFILL }},

        { &ofp_switch_features_capabilities_hdr,
          { "Capabilities", "of.sf_capabilities", FT_UINT32, BASE_HEX, NO_STRINGS, NO_MASK, "Capabilities", HFILL }},

        { &ofp_switch_features_capabilities[0],
          { "  Flow statistics", "of.sf_capabilities_flow_stats", FT_UINT32, BASE_DEC, VALS(names_choice), OFPC_FLOW_STATS, "Flow statistics", HFILL }},

        { &ofp_switch_features_capabilities[1],
          { "  Table statistics", "of.sf_capabilities_table_stats", FT_UINT32, BASE_DEC, VALS(names_choice), OFPC_TABLE_STATS, "Table statistics", HFILL }},

        { &ofp_switch_features_capabilities[2],
          { "  Port statistics", "of.sf_capabilities_port_stats", FT_UINT32, BASE_DEC, VALS(names_choice), OFPC_PORT_STATS, "Port statistics", HFILL }},

        { &ofp_switch_features_capabilities[3],
          { "  802.11d spanning tree", "of.sf_capabilities_stp", FT_UINT32, BASE_DEC, VALS(names_choice), OFPC_STP, "802.11d spanning tree", HFILL }},

        { &ofp_switch_features_capabilities[4],
          { "  Reserved", "of.sf_capabilities_reserved", FT_UINT32, BASE_DEC, VALS(names_choice), OFPC_RESERVED,  "Reserved", HFILL }},

        { &ofp_switch_features_capabilities[5],
          { "  Can reassemble IP fragments", "of.sf_capabilities_ip_reasm", FT_UINT32, BASE_DEC, VALS(names_choice), OFPC_IP_REASM,  "Can reassemble IP fragments", HFILL }},

        { &ofp_switch_features_capabilities[6],
          { "  Queue statistics", "of.sf_capabilities_queue_stats", FT_UINT32, BASE_DEC, VALS(names_choice), OFPC_QUEUE_STATS,  "Queue statistics", HFILL }},

        { &ofp_switch_features_capabilities[7],
          { "  Match IP addresses in ARP pkts", "of.sf_capabilities_arp_match_ip", FT_UINT32, BASE_DEC, VALS(names_choice), OFPC_ARP_MATCH_IP,  "Match IP addresses in ARP pkts", HFILL }},

        { &ofp_switch_features_actions_hdr,
          { "Actions", "of.sf_actions", FT_UINT32, BASE_HEX, NO_STRINGS, NO_MASK, "Actions", HFILL }},

        { &ofp_switch_features_actions_warn,
          { "Warning: Actions are meaningless until version 0x90", "of.sf_actions_warn", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Warning", HFILL }},

        { &ofp_switch_features_actions[0],
          { "  Output to switch port", "of.sf_actions_output", FT_UINT32, BASE_DEC, VALS(names_choice), 1 << OFPAT_OUTPUT, "Output to switch port", HFILL }},

        { &ofp_switch_features_actions[1],
          { "  Set the 802.1q VLAN id", "of.sf_actions_set_vlan_vid", FT_UINT32, BASE_DEC, VALS(names_choice), 1 << OFPAT_SET_VLAN_VID, "Set the 802.1q VLAN id", HFILL }},

        { &ofp_switch_features_actions[2],
          { "  Set the 802.1q priority", "of.sf_actions_set_vlan_pcp", FT_UINT32, BASE_DEC, VALS(names_choice), 1 << OFPAT_SET_VLAN_PCP, "Set the 802.1q VLAN priority", HFILL }},

        { &ofp_switch_features_actions[3],
          { "  Strip the 802.1q header", "of.sf_actions_strip_vlan", FT_UINT32, BASE_DEC, VALS(names_choice), 1 << OFPAT_STRIP_VLAN, "Strip the 802.1q header", HFILL }},

        { &ofp_switch_features_actions[4],
          { "  Ethernet source address", "of.sf_actions_eth_src_addr", FT_UINT32, BASE_DEC, VALS(names_choice), 1 << OFPAT_SET_DL_SRC, "Ethernet source address", HFILL }},

        { &ofp_switch_features_actions[5],
          { "  Ethernet destination address", "of.sf_actions_eth_dst_addr", FT_UINT32, BASE_DEC, VALS(names_choice), 1 << OFPAT_SET_DL_DST, "Ethernet destination address", HFILL }},

        { &ofp_switch_features_actions[6],
          { "  IP source address", "of.sf_actions_ip_src_addr", FT_UINT32, BASE_DEC, VALS(names_choice), 1 << OFPAT_SET_NW_SRC, "IP source address", HFILL }},

        { &ofp_switch_features_actions[7],
          { "  IP destination address", "of.sf_actions_ip_dst_addr", FT_UINT32, BASE_DEC, VALS(names_choice), 1 << OFPAT_SET_NW_DST, "IP destination address", HFILL }},

        { &ofp_switch_features_actions[8],
          { "  Set IP TOS bits", "of.sf_actions_ip_tos", FT_UINT32, BASE_DEC, VALS(names_choice), 1 << OFPAT_SET_NW_TOS, "Set IP TOS bits", HFILL }},

        { &ofp_switch_features_actions[9],
          { "  TCP/UDP source", "of.sf_actions_src_port", FT_UINT32, BASE_DEC, VALS(names_choice), 1 << OFPAT_SET_TP_SRC, "TCP/UDP source port", HFILL }},

        { &ofp_switch_features_actions[10],
          { "  TCP/UDP destination", "of.sf_actions_dst_port", FT_UINT32, BASE_DEC, VALS(names_choice), 1 << OFPAT_SET_TP_DST, "TCP/UDP destination port", HFILL }},

        { &ofp_switch_features_actions[11],
          { "  Enqueue port queue", "of.sf_actions_enqueue", FT_UINT32, BASE_DEC, VALS(names_choice), 1 << OFPAT_ENQUEUE, "Enqueue to port queue", HFILL }},


        { &ofp_switch_features_ports_hdr,
          { "Port Definitions", "of.sf_ports", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Port Definitions", HFILL }},

        { &ofp_switch_features_ports_num,
          { "# of Ports", "of.sf_ports_num", FT_UINT32, BASE_DEC, NO_STRINGS, NO_MASK, "Number of Ports", HFILL }},

        { &ofp_switch_features_ports_warn,
          { "Warning", "of.sf_ports_warn", FT_STRING, BASE_NONE, NO_STRINGS, NO_MASK, "Warning", HFILL }},


        /* CSM: Get Config Request */
        /* nothing beyond the header */

        /* CSM: Get Config Reply */
        /* CSM: Set Config */
        { &ofp_switch_config,
          { "Switch Configuration", "of.sc", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Switch Configuration", HFILL } },

        { &ofp_switch_config_flags_hdr,
          { "Flags", "of.sc_flags", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Flags", HFILL } },

        { &ofp_switch_config_flags_ip_frag,
          { "  Handling of IP fragments", "of.sc_flags_ip_frag", FT_UINT16, BASE_DEC, VALS(sc_frag_choices), OFPC_FRAG_MASK, "Handling of IP fragments", HFILL }},

/*        { &ofp_switch_config_flags[1],
          { "  No special fragment handling", "of.sc_flags_frag_normal", FT_UINT32, BASE_DEC, VALS(names_choice), OFPC_FRAG_NORMAL, "No special fragment handling", HFILL }},

        { &ofp_switch_config_flags[2],
          { "  Drop fragments", "of.sc_flags_frag_drop", FT_UINT32, BASE_DEC, VALS(names_choice), OFPC_FRAG_DROP, "Drop fragments", HFILL }},

        { &ofp_switch_config_flags[3],
          { "  Reassemble (only if OFPC_IP_REASM set)", "of.sc_flags_frag_reasm", FT_UINT32, BASE_DEC, VALS(names_choice), OFPC_FRAG_REASM, "Reassemble (only if OFPC_IP_REASM set)", HFILL }},

*/
        { &ofp_switch_config_miss_send_len,
          { "Max Bytes of New Flow to Send to Controller", "of.sc_miss_send_len", FT_UINT16, BASE_DEC, NO_STRINGS, NO_MASK, "Max Bytes of New Flow to Send to Controller", HFILL } },

        /* Queue config request/reply */
        { &ofp_queue_get_config_request,
          { "Queue Configuration Request", "of.queue_req", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Queue Configuration Request", HFILL } },

        { &ofp_queue_get_config_request_port_no,
          { "Port #", "of.queue_port_no", FT_STRING, BASE_NONE, NO_STRINGS, NO_MASK, "Port #", HFILL }},

        { &ofp_queue_get_config_reply,
          { "Queue Configuration Reply", "of.queue_repr", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Queue Configuration Reply", HFILL } },

        { &ofp_queue_get_config_reply_port_no,
          { "Port #", "of.queue_port_no", FT_STRING, BASE_NONE, NO_STRINGS, NO_MASK, "Port #", HFILL }},

        { &ofp_queue_get_config_reply_queues_hdr,
          { "Queue Definitions", "of.qr_queues", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Queue Definitions", HFILL }},

        { &ofp_queue_get_config_reply_queues_num,
          { "# of Queues", "of.qr_queues_num", FT_UINT32, BASE_DEC, NO_STRINGS, NO_MASK, "Number of Queues", HFILL }},

        { &ofp_packet_queue,
          { "Queue", "of.packet_queue", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Queue", HFILL }},

        { &ofp_packet_queue_queue_id,
          { "Queue ID", "of.packet_queue", FT_STRING, BASE_NONE, NO_STRINGS, NO_MASK, "Queue ID", HFILL }},

        { &ofp_packet_queue_len,
          { "Len", "of.packet_queue_len", FT_UINT16, BASE_DEC, NO_STRINGS, NO_MASK, "Len", HFILL }},

        { &ofp_packet_queue_warn,
          { "Warning", "of.packet_queue_warn", FT_STRING, BASE_NONE, NO_STRINGS, NO_MASK, "Warning", HFILL }},

        { &ofp_packet_queue_property,
          { "Queue Property", "of.packet_queue_prop", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Queue Property", HFILL }},

        { &ofp_packet_queue_property_len,
          { "Len", "of.packet_queue_prop_len", FT_UINT16, BASE_DEC, NO_STRINGS, NO_MASK, "Len", HFILL }},

        { &ofp_packet_queue_property_type,
          { "Type", "of.packet_queue_prop_type", FT_UINT16, BASE_DEC, VALS(names_ofp_packet_queue_property_type), NO_MASK, "Type", HFILL }},

        { &ofp_packet_queue_property_rate,
          { "Rate", "of.packet_queue_prop_rate", FT_UINT16, BASE_DEC, NO_STRINGS, NO_MASK, "Rate", HFILL }},

        { &ofp_packet_queue_properties_hdr,
          { "Property Definitions", "of.qr_queue_properties", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Property Definitions", HFILL }},

        { &ofp_packet_queue_properties_num,
          { "# of Properties", "of.qr_queue_properties_num", FT_UINT32, BASE_DEC, NO_STRINGS, NO_MASK, "Number of Properties", HFILL }},

        { &ofp_packet_queue_property_unknown,
          { "Unknown Property Type", "of.queue_property_unknown", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Unknown Property Type", HFILL }},

        { &ofp_packet_queue_property_warn,
          { "Warning", "of.queue_property_warn", FT_STRING, BASE_NONE, NO_STRINGS, NO_MASK, "Warning", HFILL }},

        /* AM:  Packet In */
        { &ofp_packet_in,
          { "Packet In", "of.pktin", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Packet In", HFILL }},

        { &ofp_packet_in_buffer_id,
          { "Buffer ID", "of.pktin_buffer_id", FT_UINT32, BASE_DEC, NO_STRINGS, NO_MASK, "Buffer ID", HFILL }},

        { &ofp_packet_in_total_len,
          { "Frame Total Length", "of.pktin_total_len", FT_UINT16, BASE_DEC, NO_STRINGS, NO_MASK, "Frame Total Length (B)", HFILL }},

        { &ofp_packet_in_in_port,
          { "Frame Recv Port", "of.pktin_in_port", FT_UINT16, BASE_DEC, NO_STRINGS, NO_MASK, "Port Frame was Received On", HFILL }},

        { &ofp_packet_in_reason,
          { "Reason Sent", "of.pktin_reason", FT_UINT8, BASE_DEC, VALS(names_ofp_packet_in_reason), NO_MASK, "Reason Packet Sent", HFILL }},

        { &ofp_packet_in_data_hdr,
          { "Frame Data", "of.pktin_data", FT_BYTES, BASE_NONE, NO_STRINGS, NO_MASK, "Frame Data", HFILL }},


        /* CSM: Packet Out */
       { &ofp_packet_out,
          { "Packet Out", "of.pktout", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Packet Out", HFILL }},

        { &ofp_packet_out_buffer_id,
          { "Buffer ID", "of.pktout_buffer_id", FT_STRING, BASE_NONE, NO_STRINGS, NO_MASK, "Buffer ID", HFILL }},

        { &ofp_packet_out_in_port,
          { "Frame Recv Port", "of.pktout_in_port", FT_STRING, BASE_NONE, NO_STRINGS, NO_MASK, "Port Frame was Received On", HFILL }},

        { &ofp_packet_out_actions_len,
          { "Size of action array in bytes", "of.pktout_actions_len", FT_UINT16, BASE_DEC, NO_STRINGS, NO_MASK, "Size of action array in bytes", HFILL }},

        { &ofp_packet_out_actions_hdr,
          { "Actions to Apply", "of.pktout_actions", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Actions to Apply to Packet", HFILL }},

        { &ofp_packet_out_data_hdr,
          { "Frame Data", "of.pktout_data", FT_BYTES, BASE_NONE, NO_STRINGS, NO_MASK, "Frame Data", HFILL }},


        /* CSM: Flow Mod */
        { &ofp_flow_mod,
          { "Flow Modification", "of.fm", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Flow Modification", HFILL } },

        { &ofp_flow_mod_cookie,
          { "Cookie", "of.fm_cookie", FT_UINT64, BASE_HEX, NO_STRINGS, NO_MASK, "Cookie", HFILL } },

        { &ofp_flow_mod_command,
          { "Command", "of.fm_command", FT_UINT16, BASE_DEC, VALS(names_flow_mod_command), NO_MASK, "Command", HFILL } },

        { &ofp_flow_mod_idle_timeout,
          { "Idle Time (sec) Before Discarding", "of.fm_max_idle", FT_UINT16, BASE_DEC, NO_STRINGS, NO_MASK, "Idle Time (sec) Before Discarding", HFILL } },

        { &ofp_flow_mod_hard_timeout,
          { "Max Time (sec) Before Discarding", "of.fm_max_idle", FT_UINT16, BASE_DEC, NO_STRINGS, NO_MASK, "Max Idle Time (sec) Before Discarding", HFILL } },

        { &ofp_flow_mod_priority,
          { "Priority", "of.fm_priority", FT_UINT16, BASE_DEC, NO_STRINGS, NO_MASK, "Priority", HFILL } },

        { &ofp_flow_mod_buffer_id,
          { "Buffer ID", "of.fm_buffer_id", FT_STRING, BASE_NONE, NO_STRINGS, NO_MASK, "Buffer ID", HFILL } },

        { &ofp_flow_mod_out_port,
          { "Out Port (delete* only)", "of.fm_out_port", FT_STRING, BASE_NONE, NO_STRINGS, NO_MASK, "Out Port (delete* only)", HFILL } },

        { &ofp_flow_mod_flags[0],
          { "Send flow removed", "of.fm_flags", FT_UINT16, BASE_DEC, VALS(names_choice), OFPFF_SEND_FLOW_REM, "Send flow removed", HFILL }},

        { &ofp_flow_mod_flags[1],
          { "Check for overlap before adding flow", "of.fm_flags", FT_UINT16, BASE_DEC, VALS(names_choice), OFPFF_CHECK_OVERLAP, "Check for overlap before adding flow", HFILL } },

        { &ofp_flow_mod_flags[2],
          { "Install flow into emergecy flow table", "of.fm_flags", FT_UINT16, BASE_DEC, VALS(names_choice), OFPFF_EMERG, "Install flow into emergency flow table", HFILL } },

        /* AM:  Flow Removed */
        { &ofp_flow_removed,
          { "Flow Removed", "of.fe", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Flow Removed", HFILL } },

        { &ofp_flow_removed_cookie,
          { "Cookie", "of.fe_cookie", FT_UINT64, BASE_HEX, NO_STRINGS, NO_MASK, "Cookie", HFILL } },

        { &ofp_flow_removed_priority,
          { "Priority", "of.fe_priority", FT_UINT16, BASE_DEC, NO_STRINGS, NO_MASK, "Priority", HFILL } },

        { &ofp_flow_removed_reason,
          { "Reason", "of.fe_reason", FT_UINT8, BASE_DEC, VALS(names_ofp_flow_removed_reason), NO_MASK, "Reason", HFILL } },

        { &ofp_flow_removed_duration_sec,
          { "Flow Duration (sec)", "of.fe_duration_sec", FT_UINT32, BASE_DEC, NO_STRINGS, NO_MASK, "Time Flow was Alive (sec)", HFILL } },

        { &ofp_flow_removed_duration_nsec,
          { "Flow Duration (nsec)", "of.fe_duration_nsec", FT_UINT32, BASE_DEC, NO_STRINGS, NO_MASK, "Time Flow was Alive (nsec)", HFILL } },

          { &ofp_flow_removed_idle_timeout,
          { "Idle Time (sec) Before Discarding", "of.fe_idle_timeout", FT_UINT16, BASE_DEC, NO_STRINGS, NO_MASK, "Idle Time (sec) Before Discarding", HFILL } },

        { &ofp_flow_removed_packet_count,
          { "Packet Count", "of.fe_packet_count", FT_UINT64, BASE_DEC, NO_STRINGS, NO_MASK, "Packet Cout", HFILL } },

        { &ofp_flow_removed_byte_count,
          { "Byte Count", "of.fe_byte_count", FT_UINT64, BASE_DEC, NO_STRINGS, NO_MASK, "Byte Count", HFILL } },


        /* CSM: Table */
        /* not yet defined by the spec */


        /* CSM: Port Mod */
        { &ofp_port_mod,
          { "Port Modification", "of.pm", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Port Modification", HFILL } },

        { &ofp_port_mod_port_no,
          { "Port #", "of.port_no", FT_STRING, BASE_NONE, NO_STRINGS, NO_MASK, "Port #", HFILL }},

        { &ofp_port_mod_hw_addr,
          { "MAC Address", "of.port_hw_addr", FT_ETHER, BASE_NONE, NO_STRINGS, NO_MASK, "MAC Address", HFILL }},

        { &ofp_port_mod_config_hdr,
          { "Port Config Flags", "of.port_config", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Config Flags", HFILL }},

        { &ofp_port_mod_config[0],
          { "  Port is administratively down", "of.port_config_port_down", FT_UINT32, BASE_DEC, VALS(names_choice), OFPPC_PORT_DOWN, "Port is administratively down", HFILL }},

        { &ofp_port_mod_config[1],
          { "  Disable 802.1D spanning tree on port", "of.port_config_no_stp", FT_UINT32, BASE_DEC, VALS(names_choice), OFPPC_NO_STP, "Disable 802.1D spanning tree on port", HFILL }},

        { &ofp_port_mod_config[2],
          { "  Drop non-802.1D packets received on port", "of.port_config_no_recv", FT_UINT32, BASE_DEC, VALS(names_choice), OFPPC_NO_RECV, "Drop non-802.1D packets received on port", HFILL }},

        { &ofp_port_mod_config[3],
          { "  Drop received 802.1D STP packets", "of.port_config_no_revc_stp", FT_UINT32, BASE_DEC, VALS(names_choice), OFPPC_NO_RECV_STP, "Drop received 802.1D STP packets", HFILL }},

        { &ofp_port_mod_config[4],
          { "  Do not include this port when flooding", "of.port_config_no_flood", FT_UINT32, BASE_DEC, VALS(names_choice), OFPPC_NO_FLOOD, "Do not include this port when flooding", HFILL }},

        { &ofp_port_mod_config[5],
          { "  Drop packets forwarded to port", "of.port_config_no_fwd", FT_UINT32, BASE_DEC, VALS(names_choice), OFPPC_NO_FWD, "Drop packets forwarded to port", HFILL }},

        { &ofp_port_mod_config[6],
          { "  Do not send packet-in msgs for port", "of.port_config_no_packet_in", FT_UINT32, BASE_DEC, VALS(names_choice), OFPPC_NO_PACKET_IN, "Do not send packet-in msgs for port", HFILL }},

        { &ofp_port_mod_mask_hdr,
          { "Port Config Mask", "of.port_mask", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Config Mask", HFILL }},

        { &ofp_port_mod_mask[0],
          { "  Port is administratively down", "of.port_mask_port_down", FT_UINT32, BASE_DEC, VALS(names_choice), OFPPC_PORT_DOWN, "Port is administratively down", HFILL }},

        { &ofp_port_mod_mask[1],
          { "  Disable 802.1D spanning tree on port", "of.port_mask_no_stp", FT_UINT32, BASE_DEC, VALS(names_choice), OFPPC_NO_STP, "Disable 802.1D spanning tree on port", HFILL }},

        { &ofp_port_mod_mask[2],
          { "  Drop non-802.1D packets received on port", "of.port_mask_no_recv", FT_UINT32, BASE_DEC, VALS(names_choice), OFPPC_NO_RECV, "Drop non-802.1D packets received on port", HFILL }},

        { &ofp_port_mod_mask[3],
          { "  Drop received 802.1D STP packets", "of.port_mask_no_revc_stp", FT_UINT32, BASE_DEC, VALS(names_choice), OFPPC_NO_RECV_STP, "Drop received 802.1D STP packets", HFILL }},

        { &ofp_port_mod_mask[4],
          { "  Do not include this port when flooding", "of.port_mask_no_flood", FT_UINT32, BASE_DEC, VALS(names_choice), OFPPC_NO_FLOOD, "Do not include this port when flooding", HFILL }},

        { &ofp_port_mod_mask[5],
          { "  Drop packets forwarded to port", "of.port_mask_no_fwd", FT_UINT32, BASE_DEC, VALS(names_choice), OFPPC_NO_FWD, "Drop packets forwarded to port", HFILL }},

        { &ofp_port_mod_mask[6],
          { "  Do not send packet-in msgs for port", "of.port_mask_no_packet_in", FT_UINT32, BASE_DEC, VALS(names_choice), OFPPC_NO_PACKET_IN, "Do not send packet-in msgs for port", HFILL }},

        { &ofp_port_mod_advertise_hdr,
          { "Port Advertise Flags", "of.port_advertise", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Advertise Flags", HFILL }},
		
        { &ofp_port_mod_advertise[0],
            { "   10 Mb half-duplex rate support", "of.port_advertise_10mb_hd" , FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_10MB_HD, "10 Mb half-duplex rate support", HFILL }},
		
        { &ofp_port_mod_advertise[1],
            { "   10 Mb full-duplex rate support", "of.port_advertise_10mb_fd",  FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_10MB_FD, "10 Mb full-duplex rate support", HFILL }},
		
        { &ofp_port_mod_advertise[2],
            { "  100 Mb half-duplex rate support", "of.port_advertise_100mb_hd", FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_100MB_HD, "100 Mb half-duplex rate support", HFILL }},
		
        { &ofp_port_mod_advertise[3],
            { "  100 Mb full-duplex rate support", "of.port_advertise_100mb_fd", FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_100MB_FD, "100 Mb full-duplex rate support", HFILL }},
		
        { &ofp_port_mod_advertise[4],
            { "    1 Gb half-duplex rate support", "of.port_advertise_1gb_hd",   FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_1GB_HD, "1 Gb half-duplex rate support", HFILL }},
		
        { &ofp_port_mod_advertise[5],
            { "    1 Gb full-duplex rate support", "of.port_advertise_1gb_fd",   FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_1GB_FD, "1 Gb full-duplex rate support", HFILL }},
		
        { &ofp_port_mod_advertise[6],
            { "   10 Gb full-duplex rate support", "of.port_advertise_10gb_hd",  FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_10GB_FD, "10 Gb full-duplex rate support", HFILL }},
		
        { &ofp_port_mod_advertise[7],
            { "   Copper medium support", "of.port_advertise_copper",  FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_COPPER, "Copper medium support", HFILL }},
		
        { &ofp_port_mod_advertise[8],
            { "   Fiber medium support", "of.port_advertise_fiber",  FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_FIBER, "Fiber medium support", HFILL }},
		
        { &ofp_port_mod_advertise[9],
            { "   Auto-negotiation support", "of.port_advertise_autoneg",  FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_AUTONEG, "Auto-negotiation support", HFILL }},
		
        { &ofp_port_mod_advertise[10],
            { "   Pause support", "of.port_advertise_pause",  FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_PAUSE, "Pause support", HFILL }},
		
        { &ofp_port_mod_advertise[11],
            { "   Asymmetric pause support", "of.port_advertise_pause_asym",  FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_PAUSE_ASYM, "Asymmetric pause support", HFILL }},



        /* AM: Port Status */
        { &ofp_port_status,
          { "Port Status", "of.ps", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Port Status", HFILL } },

        { &ofp_port_status_reason,
          { "Reason", "of.ps_reason", FT_UINT8, BASE_DEC, VALS(names_ofp_port_reason), NO_MASK, "Reason", HFILL } },


        /* CSM: Stats Request */
        { &ofp_stats_request,
          { "Stats Request", "of.sreq", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Statistics Request", HFILL } },

        { &ofp_stats_request_type,
          { "Type", "of.sreq_type", FT_UINT16, BASE_HEX, VALS(names_stats_types), NO_MASK, "Type", HFILL } },

        { &ofp_stats_request_flags,
          { "Flags", "of.sreq_flags", FT_UINT16, BASE_HEX, NO_STRINGS, NO_MASK, "Flags", HFILL } },

        { &ofp_stats_request_body,
          { "Body", "of.sreq_body", FT_BYTES, BASE_NONE, NO_STRINGS, NO_MASK, "Body", HFILL } },



        /* CSM: Stats Reply */
        { &ofp_stats_reply,
          { "Stats Reply", "of.srep", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Statistics Reply", HFILL } },

        { &ofp_stats_reply_type,
          { "Type", "of.srep_type", FT_UINT16, BASE_HEX, VALS(names_stats_types), NO_MASK, "Type", HFILL } },

        { &ofp_stats_reply_flags,
          { "Flags", "of.srep_flags", FT_UINT16, BASE_DEC, NO_STRINGS, NO_MASK, "Flags", HFILL } },

        { &ofp_stats_reply_flag[0],
          { "  More replies to follow", "of.srep_more", FT_UINT16, BASE_DEC, VALS(names_choice), OFPSF_REPLY_MORE, "More replies to follow", HFILL }},

        { &ofp_stats_reply_body,
          { "Body", "of.srep_body", FT_BYTES, BASE_NONE, NO_STRINGS, NO_MASK, "Body", HFILL } },

        /* CSM: Stats: Desc: Reply */
        { &ofp_desc_stats,
          { "Desc Stats Reply", "of.stats_desc", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Desc Statistics Reply", HFILL } },

        { &ofp_desc_stats_mfr_desc,
          { "Mfr Desc", "of.stats_desc_mfr_desc", FT_STRING, BASE_NONE, NO_STRINGS, NO_MASK, "Mfr Desc", HFILL } },

        { &ofp_desc_stats_hw_desc,
          { "HW Desc", "of.stats_desc_hw_desc", FT_STRING, BASE_NONE, NO_STRINGS, NO_MASK, "HW Desc", HFILL } },

        { &ofp_desc_stats_sw_desc,
          { "SW Desc", "of.stats_desc_sw_desc", FT_STRING, BASE_NONE, NO_STRINGS, NO_MASK, "SW Desc", HFILL } },

        { &ofp_desc_stats_serial_num,
          { "Serial Num", "of.stats_desc_serial_num", FT_STRING, BASE_NONE, NO_STRINGS, NO_MASK, "Serial Num", HFILL } },

        { &ofp_desc_stats_dp_desc,
          { "DP Desc", "of.stats_desc_dp_desc", FT_STRING, BASE_NONE, NO_STRINGS, NO_MASK, "DP Comment", HFILL } },

        /* CSM: Stats: Flow: Request */
        { &ofp_flow_stats_request,
          { "Flow Stats Request", "of.stats_flow", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Flow Statistics Request", HFILL } },

        { &ofp_flow_stats_request_table_id,
          { "Table ID", "of.stats_flow_table_id", FT_STRING, BASE_NONE, NO_STRINGS, NO_MASK, "Table ID", HFILL } },

        { &ofp_flow_stats_request_out_port,
          { "Out Port", "of.stats_flow_table_id", FT_STRING, BASE_NONE, NO_STRINGS, NO_MASK, "Out Port", HFILL } },

        /* CSM: Stats: Flow: Reply */
        { &ofp_flow_stats_reply,
          { "Flow Stats Reply", "of.stats_flow_", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Flow Statistics Reply", HFILL } },

        { &ofp_flow_stats_reply_table_id,
          { "Table ID", "of.stats_flow_table_id", FT_UINT8, BASE_DEC, NO_STRINGS, NO_MASK, "Table ID", HFILL } },

        { &ofp_flow_stats_reply_duration_sec,
          { "Flow Duration (sec)", "of.stats_flow_duration_sec", FT_UINT32, BASE_DEC, NO_STRINGS, NO_MASK, "Time Flow has Been Alive (sec)", HFILL } },

        { &ofp_flow_stats_reply_duration_nsec,
          { "Flow Duration (nsec)", "of.stats_flow_duration_nsec", FT_UINT32, BASE_DEC, NO_STRINGS, NO_MASK, "Time Flow has Been Alive (nsec)", HFILL } },

        { &ofp_flow_stats_reply_cookie,
          { "Cookie", "of.stats_flow_cookie", FT_UINT64, BASE_HEX, NO_STRINGS, NO_MASK, "Cookie", HFILL } },

        { &ofp_flow_stats_reply_priority,
          { "Priority", "of.stats_flow_priority", FT_UINT16, BASE_DEC, NO_STRINGS, NO_MASK, "Priority", HFILL } },

        { &ofp_flow_stats_reply_idle_timeout,
          { "Number of seconds idle before expiration", "of.stats_flow_idle_timeout", FT_UINT16, BASE_DEC, NO_STRINGS, NO_MASK, "Number of seconds idle before expiration", HFILL } },

        { &ofp_flow_stats_reply_hard_timeout,
          { "Number of seconds before expiration", "of.stats_flow_hard_timeout", FT_UINT16, BASE_DEC, NO_STRINGS, NO_MASK, "Number of seconds before expiration", HFILL } },

        { &ofp_flow_stats_reply_packet_count,
          { "Packet Count", "of.stats_flow_packet_count", FT_UINT64, BASE_DEC, NO_STRINGS, NO_MASK, "Packet Count", HFILL } },

        { &ofp_flow_stats_reply_byte_count,
          { "Byte Count", "of.stats_flow_byte_count", FT_UINT64, BASE_DEC, NO_STRINGS, NO_MASK, "Byte Count", HFILL } },

        /* CSM: Stats: Aggregate: Request */
        { &ofp_aggr_stats_request,
          { "Aggregate Stats Request", "of.stats_aggr", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Aggregate Statistics Request", HFILL } },

        { &ofp_aggr_stats_request_table_id,
          { "Table ID", "of.stats_aggr_table_id", FT_STRING, BASE_NONE, NO_STRINGS, NO_MASK, "Table ID", HFILL } },

        /* CSM: Stats: Aggregate: Reply */
        { &ofp_aggr_stats_reply,
          { "Aggregate Stats Reply", "of.stats_aggr", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Aggregate Statistics Reply", HFILL } },

        { &ofp_aggr_stats_reply_packet_count,
          { "Packet Count", "of.stats_aggr_packet_count", FT_UINT64, BASE_DEC, NO_STRINGS, NO_MASK, "Packet count", HFILL } },

        { &ofp_aggr_stats_reply_byte_count,
          { "Byte Count", "of.stats_aggr_byte_count", FT_UINT64, BASE_DEC, NO_STRINGS, NO_MASK, "Byte Count", HFILL } },

        { &ofp_aggr_stats_reply_flow_count,
          { "Flow Count", "of.stats_aggr_flow_count", FT_UINT32, BASE_DEC, NO_STRINGS, NO_MASK, "Flow Count", HFILL } },

        /* CSM: Stats: Port */
        { &ofp_port_stats_request,
          { "Port Stats Request", "of.stats_port_request", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Port Statistics Request", HFILL } },

        { &ofp_port_stats_request_port_no,
          { "Port #", "of.stats_port_request_port_no", FT_STRING, BASE_NONE, NO_STRINGS, NO_MASK, "", HFILL } },

        { &ofp_port_stats,
          { "Port Stats", "of.stats_port", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Port Stats", HFILL } },

        { &ofp_port_stats_port_no,
          { "Port #", "of.stats_port_port_no", FT_STRING, BASE_NONE, NO_STRINGS, NO_MASK, "", HFILL } },

        { &ofp_port_stats_rx_packets,
          { "# Received packets", "of.stats_port_rx_packets", FT_UINT64, BASE_DEC, NO_STRINGS, NO_MASK, "# Received packets", HFILL } },

        { &ofp_port_stats_tx_packets,
          { "# Transmitted packets", "of.stats_port_tx_packets", FT_UINT64, BASE_DEC, NO_STRINGS, NO_MASK, "# Transmitted packets", HFILL } },

        { &ofp_port_stats_rx_bytes,
          { "# Received bytes", "of.stats_port_rx_bytes", FT_UINT64, BASE_DEC, NO_STRINGS, NO_MASK, "# Received bytes", HFILL } },

        { &ofp_port_stats_tx_bytes,
          { "# Transmitted bytes", "of.stats_port_tx_bytes", FT_UINT64, BASE_DEC, NO_STRINGS, NO_MASK, "# Transmitted bytes", HFILL } },

        { &ofp_port_stats_rx_dropped,
          { "# RX dropped", "of.stats_port_rx_dropped", FT_UINT64, BASE_DEC, NO_STRINGS, NO_MASK, "# RX dropped", HFILL } },

        { &ofp_port_stats_tx_dropped,
          { "# TX dropped", "of.stats_port_tx_dropped", FT_UINT64, BASE_DEC, NO_STRINGS, NO_MASK, "# TX dropped", HFILL } },

        { &ofp_port_stats_rx_errors,
          { "# RX errors", "of.stats_port_rx_errors", FT_UINT64, BASE_DEC, NO_STRINGS, NO_MASK, "# RX errors", HFILL } },

        { &ofp_port_stats_tx_errors,
          { "# TX errors", "of.stats_port_tx_errors", FT_UINT64, BASE_DEC, NO_STRINGS, NO_MASK, "# TX errors", HFILL } },

        { &ofp_port_stats_rx_frame_err,
          { "# RX frame errors", "of.stats_port_rx_frame_err", FT_UINT64, BASE_DEC, NO_STRINGS, NO_MASK, "# RX frame alignment errors", HFILL } },

        { &ofp_port_stats_rx_over_err,
          { "# RX overrun errors", "of.stats_port_rx_over_err", FT_UINT64, BASE_DEC, NO_STRINGS, NO_MASK, "# RX overrun errors", HFILL } },

        { &ofp_port_stats_rx_crc_err,
          { "# RX CRC errors", "of.stats_port_rx_crc_err", FT_UINT64, BASE_DEC, NO_STRINGS, NO_MASK, "# RX crc errors", HFILL } },

        { &ofp_port_stats_collisions,
          { "# Collisions", "of.stats_port_collisions", FT_UINT64, BASE_DEC, NO_STRINGS, NO_MASK, "Number of collisions", HFILL } },

        /* CSM: Stats: Queue */
        { &ofp_queue_stats_request,
          { "Queue Stats Request", "of.stats_flow", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Queue Statistics Request", HFILL } },

        { &ofp_queue_stats,
          { "Queue Stats", "of.stats_queue", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Queue Stats", HFILL } },

        { &ofp_queue_stats_port_no,
          { "Port #", "of.stats_queue_port_no", FT_STRING, BASE_NONE, NO_STRINGS, NO_MASK, "", HFILL } },

        { &ofp_queue_stats_queue_id,
          { "Queue ID","of.stats_queue_queue_id", FT_STRING, BASE_NONE, NO_STRINGS, NO_MASK, "Queue ID", HFILL } },

        { &ofp_queue_stats_tx_bytes,
          { "# Transmitted bytes", "of.stats_queu_tx_bytes", FT_UINT64, BASE_DEC, NO_STRINGS, NO_MASK, "# Transmitted bytes", HFILL } },

        { &ofp_queue_stats_tx_packets,
          { "# Transmitted packets", "of.stats_queue_tx_packets", FT_UINT64, BASE_DEC, NO_STRINGS, NO_MASK, "# Transmitted packets", HFILL } },

        { &ofp_queue_stats_tx_errors,
          { "# Transmit errors", "of.stats_queue_tx_errors", FT_UINT64, BASE_DEC, NO_STRINGS, NO_MASK, "# Transmit errors", HFILL } },

        /* CSM: Stats: Table */
        { &ofp_table_stats,
          { "Table Stats", "of.stats_table", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Table Stats", HFILL } },

        { &ofp_table_stats_table_id,
          { "Table ID", "of.stats_table_table_id", FT_UINT8, BASE_DEC, NO_STRINGS, NO_MASK, "Table ID", HFILL } },

        { &ofp_table_stats_name,
          { "Name", "of.stats_table_name", FT_STRING, BASE_NONE, NO_STRINGS, NO_MASK, "Name", HFILL } },

        { &ofp_table_stats_wildcards_hdr,
          { "Wildcards", "of.stats_table_wildcards", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Wildcards", HFILL } },

        { &ofp_table_stats_max_entries,
          { "Max Supported Entries", "of.stats_table_max_entries", FT_UINT32, BASE_DEC, NO_STRINGS, NO_MASK, "Max Supported Entries", HFILL } },

        { &ofp_table_stats_active_count,
          { "Active Entry Count", "of.stats_table_active_count", FT_UINT32, BASE_DEC, NO_STRINGS, NO_MASK, "Active Entry Count", HFILL } },

        { &ofp_table_stats_lookup_count,
          { "Lookup Count", "of.stats_table_lookup_count", FT_UINT64, BASE_DEC, NO_STRINGS, NO_MASK, "Lookup Count", HFILL } },

        { &ofp_table_stats_matched_count,
          { "Packet Match Count", "of.stats_table_match_count", FT_UINT64, BASE_DEC, NO_STRINGS, NO_MASK, "Packet Match Count", HFILL } },

        { &ofp_vendor_stats_vendor,
          { "Vendor ID", "of.stats_vendor_vendor", FT_UINT32, BASE_DEC, NO_STRINGS, NO_MASK, "Vendor ID", HFILL } },

        { &ofp_vendor_stats_body,
          { "Vendor Stats Body", "of.stats_vendor_body", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Vendor Stats Body", HFILL } },

        { &ofp_vendor,
          { "Vendor Message Body", "of.vendor", FT_BYTES, BASE_NONE, NO_STRINGS, NO_MASK, "Vendor Message Body", HFILL } },

        /* AM:  Error Message */
        { &ofp_error_msg,
          { "Error Message", "of.err", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Error Message", HFILL } },

        { &ofp_error_msg_type,
          { "Type", "of.err_type", FT_UINT16, BASE_DEC, VALS(names_ofp_error_type_reason), NO_MASK, "Type", HFILL } },

        { &ofp_error_msg_code,
          { "Code", "of.err_code", FT_UINT16, BASE_DEC, NO_STRINGS, NO_MASK, "Code", HFILL } },

        { &ofp_error_msg_data_str,
          { "Data", "of.err_data", FT_STRING, BASE_NONE, NO_STRINGS, NO_MASK, "Data", HFILL } },

        { &ofp_error_msg_data,
          { "Data", "of.err_data", FT_BYTES, BASE_NONE, NO_STRINGS, NO_MASK, "Data", HFILL } },
    };

    static gint *ett[] = {
        &ett_ofp,
        &ett_ofp_header,
        &ett_ofp_phy_port,
        &ett_ofp_phy_port_config_hdr,
        &ett_ofp_phy_port_state_hdr,
        &ett_ofp_phy_port_curr_hdr,
        &ett_ofp_phy_port_advertised_hdr,
        &ett_ofp_phy_port_supported_hdr,
        &ett_ofp_phy_port_peer_hdr,
        &ett_ofp_match,
        &ett_ofp_match_wildcards_hdr,
        &ett_ofp_action,
        &ett_ofp_action_output,
        &ett_ofp_action_enqueue,
        &ett_ofp_packet_queue_root,
        &ett_ofp_packet_queue,
        &ett_ofp_packet_queue_property,
        &ett_ofp_packet_queue_properties_hdr,
        &ett_ofp_switch_features,
        &ett_ofp_switch_features_capabilities_hdr,
        &ett_ofp_switch_features_actions_hdr,
        &ett_ofp_switch_features_ports_hdr,
        &ett_ofp_switch_config,
        &ett_ofp_switch_config_flags_hdr,
        &ett_ofp_flow_mod,
        &ett_ofp_flow_mod_flags_hdr,
        &ett_ofp_port_mod,
        &ett_ofp_port_mod_config_hdr,
        &ett_ofp_port_mod_mask_hdr,
        &ett_ofp_port_mod_advertise_hdr,
        &ett_ofp_queue_get_config_request,
        &ett_ofp_queue_get_config_reply,
        &ett_ofp_queue_get_config_reply_queues_hdr,
        &ett_ofp_stats_request,
        &ett_ofp_stats_reply,
        &ett_ofp_stats_reply_flags,
        &ett_ofp_desc_stats,
        &ett_ofp_flow_stats_request,
        &ett_ofp_flow_stats_reply,
        &ett_ofp_aggr_stats_request,
        &ett_ofp_aggr_stats_reply,
        &ett_ofp_table_stats,
        &ett_ofp_port_stats_request,
        &ett_ofp_port_stats,
        &ett_ofp_queue_stats_request,
        &ett_ofp_queue_stats,
        &ett_ofp_packet_out,
        &ett_ofp_packet_out_data_hdr,
        &ett_ofp_packet_out_actions_hdr,
        &ett_ofp_packet_in,
        &ett_ofp_packet_in_data_hdr,
        &ett_ofp_flow_removed,
        &ett_ofp_port_status,
        &ett_ofp_error_msg,
        &ett_ofp_error_msg_data,
    };

    proto_openflow = proto_register_protocol( "OpenFlow Protocol",
                                              "OFP",
                                              "of" ); /* abbreviation for filters */

    proto_register_field_array(proto_openflow, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    register_dissector("openflow", dissect_openflow, proto_openflow);
}

const char* ofp_type_to_string( gint8 type ) {
    static char str_unknown[17];

    if( type <= OFP_TYPE_MAX_VALUE )
        return names_ofp_type[type].strptr;
    else {
        snprintf( str_unknown, 17, "Unknown Type %u", type );
        return str_unknown;
    }
}

/**
 * Adds "hf" to "tree" starting at "offset" into "tvb" and using "length"
 * bytes.  offset is incremented by length.
 */
static void add_child( proto_item* tree, gint hf, tvbuff_t *tvb, guint32* offset, guint32 len ) {
    proto_tree_add_item( tree, hf, tvb, *offset, len, FALSE );
    *offset += len;
}

/**
 * Adds "hf" to "tree" starting at "offset" into "tvb" and using "length"
 * bytes.  offset is incremented by length.  The specified string is used as the
 * field's display value.
 */
static void add_child_str(proto_item* tree, gint hf, tvbuff_t *tvb, guint32* offset, guint32 len, const char* str) {
    proto_tree_add_string(tree, hf, tvb, *offset, len, str);
    *offset += len;
}

/**
 * Adds "hf" to "tree" starting at "offset" into "tvb" and using "length"
 * bytes.  The specified string is used as the
 * field's display value.
 */
static void add_child_str_const(proto_item* tree, gint hf, tvbuff_t *tvb, guint32 offset, guint32 len, const char* str) {
    proto_tree_add_string(tree, hf, tvb, offset, len, str);
}


/**
 * Adds "hf" to "tree" starting at "offset" into "tvb" and using "length" bytes.
 */
static void add_child_const( proto_item* tree, gint hf, tvbuff_t *tvb, guint32 offset, guint32 len ) {
    proto_tree_add_item( tree, hf, tvb, offset, len, FALSE );
}

/** returns the length of a PDU which starts at the specified offset in tvb. */
static guint get_openflow_message_len(packet_info *pinfo, tvbuff_t *tvb, int offset) {
    return (guint)tvb_get_ntohs(tvb, offset+2); /* length is at offset 2 in the header */
}

static void dissect_pad(proto_tree* tree, guint32 *offset, guint pad_byte_count) {
#if SHOW_PADDING
    guint i;
    for( i=0; i<pad_byte_count; i++ )
        add_child(tree, ofp_pad, tvb, offset, 1);
#else
    *offset += pad_byte_count;
#endif
}

static void dissect_port(proto_tree* tree, gint hf, tvbuff_t *tvb, guint32 *offset) {
    /* get the port number */
    guint16 port = tvb_get_ntohs( tvb, *offset );

    /* check to see if the port is special (e.g. the name of a fake output ports defined by ofp_port) */
    const char* str_port = NULL;
    char str_num[6];
    switch( port ) {

    case OFPP_IN_PORT:
        str_port = "In Port  (send the packet out the input port; This virtual port must be explicitly used  in order to send back out of the input port. )";
        break;

    case OFPP_TABLE:
        str_port = "Table  (perform actions in flow table; only allowed for dst port packet out messages)";
        break;

    case OFPP_NORMAL:
        str_port = "Normal  (process with normal L2/L3 switching)";
        break;

    case OFPP_FLOOD:
        str_port = "Flood  (all physical ports except input port and those disabled by STP)";
        break;

    case OFPP_ALL:
        str_port = "All  (all physical ports except input port)";
        break;

    case OFPP_CONTROLLER:
        str_port = "Controller  (send to controller)";
        break;

    case OFPP_LOCAL:
        str_port = "Local  (local openflow \"port\")";
        break;

    case OFPP_NONE:
        str_port = "None  (not associated with a physical port)";
        break;

    default:
        /* no special name, so just use the number */
        str_port = str_num;
        snprintf(str_num, 6, "%u", port);
    }

    /* put the string-representation in the GUI tree */
    add_child_str( tree, hf, tvb, offset, 2, str_port );
}

static void dissect_phy_ports(proto_tree* tree, proto_item* item, tvbuff_t *tvb, packet_info *pinfo, guint32 *offset, guint num_ports)
{
    proto_item *port_item;
    proto_tree *port_tree;
    proto_item *config_item;
    proto_tree *config_tree;
    proto_tree *state_item;
    proto_tree *state_tree;
    proto_item *curr_item;
    proto_tree *curr_tree;
    proto_item *advertised_item;
    proto_tree *advertised_tree;
    proto_item *supported_item;
    proto_tree *supported_tree;
    proto_item *peer_item;
    proto_tree *peer_tree;

    int i;
    while(num_ports-- > 0) {
        port_item = proto_tree_add_item(tree, ofp_phy_port, tvb, *offset, sizeof(struct ofp_phy_port), FALSE);
        port_tree = proto_item_add_subtree(port_item, ett_ofp_phy_port);

        dissect_port( port_tree, ofp_phy_port_port_no, tvb, offset );
        add_child( port_tree, ofp_phy_port_hw_addr, tvb, offset, OFP_ETH_ALEN );
        add_child( port_tree, ofp_phy_port_name, tvb, offset, OFP_MAX_PORT_NAME_LEN );

        /* config */
        config_item = proto_tree_add_item(port_tree, ofp_phy_port_config_hdr, tvb, *offset, 4, FALSE);
        config_tree = proto_item_add_subtree(config_item, ett_ofp_phy_port_config_hdr);
        for(i=0; i<NUM_PORT_CONFIG_FLAGS; i++) {
            add_child_const(config_tree, ofp_phy_port_config[i], tvb, *offset, 4);
        }
        *offset += 4;

        /* state */
        state_item = proto_tree_add_item(port_tree, ofp_phy_port_state_hdr, tvb, *offset, 4, FALSE);
        state_tree = proto_item_add_subtree(state_item, ett_ofp_phy_port_state_hdr);

        /* grab the stp state */
        guint32 state = tvb_get_ntohl( tvb, *offset );
        /*
        if (state & OFPPS_LINK_DOWN)
        	add_child_const(state_tree, ofp_phy_port_state[0], tvb, *offset, 4);
        */
        if (state & OFPPS_LINK_DOWN)
        	add_child_const(state_tree, ofp_phy_port_state_not_evil, tvb, *offset, 4);

        guint32 stp_state = state & OFPPS_STP_MASK;
        if (stp_state == OFPPS_STP_LISTEN)
        	add_child_str_const( state_tree, ofp_phy_port_state_stp_state, tvb, *offset, 4, "Not learning or relaying frames" );
        else if (stp_state == OFPPS_STP_LEARN)
        	add_child_str_const( state_tree, ofp_phy_port_state_stp_state, tvb, *offset, 4, "Learning but not relaying frames" );        	
        else if (stp_state == OFPPS_STP_FORWARD)
        	add_child_str_const( state_tree, ofp_phy_port_state_stp_state, tvb, *offset, 4, "Learning and relaying frames" );
        else if (stp_state == OFPPS_STP_BLOCK)
        	add_child_str_const( state_tree, ofp_phy_port_state_stp_state, tvb, *offset, 4, "Not part of spanning tree" );        	
        else
        	add_child_str_const( state_tree, ofp_phy_port_state_stp_state, tvb, *offset, 4, "Unknown STP state" );

        *offset += 4;

        /* curr */
        curr_item = proto_tree_add_item(port_tree, ofp_phy_port_curr_hdr, tvb, *offset, 4, FALSE);
        curr_tree = proto_item_add_subtree(curr_item, ett_ofp_phy_port_curr_hdr);
        for(i=0; i<NUM_PORT_FEATURES_FLAGS; i++) {
            add_child_const(curr_tree, ofp_phy_port_curr[i], tvb, *offset, 4);
        }
        *offset += 4;

        /* advertised */
        advertised_item = proto_tree_add_item(port_tree, ofp_phy_port_advertised_hdr, tvb, *offset, 4, FALSE);
        advertised_tree = proto_item_add_subtree(advertised_item, ett_ofp_phy_port_advertised_hdr);
        for(i=0; i<NUM_PORT_FEATURES_FLAGS; i++) {
            add_child_const(advertised_tree, ofp_phy_port_advertised[i], tvb, *offset, 4);
        }
        *offset += 4;

        /* supported */
        supported_item = proto_tree_add_item(port_tree, ofp_phy_port_supported_hdr, tvb, *offset, 4, FALSE);
        supported_tree = proto_item_add_subtree(supported_item, ett_ofp_phy_port_supported_hdr);
        for(i=0; i<NUM_PORT_FEATURES_FLAGS; i++) {
            add_child_const(supported_tree, ofp_phy_port_supported[i], tvb, *offset, 4);
        }
        *offset += 4;

        /* peer */
        peer_item = proto_tree_add_item(port_tree, ofp_phy_port_peer_hdr, tvb, *offset, 4, FALSE);
        peer_tree = proto_item_add_subtree(peer_item, ett_ofp_phy_port_peer_hdr);
        for(i=0; i<NUM_PORT_FEATURES_FLAGS; i++) {
            add_child_const(peer_tree, ofp_phy_port_peer[i], tvb, *offset, 4);
        }
        *offset += 4;
    }
}

static void dissect_queue_id(proto_tree* tree, gint hf, tvbuff_t *tvb, guint32 *offset) {
    /* get the queue_id */
    guint32 queue_id = tvb_get_ntohl( tvb, *offset);

    /* check to see if it is any special id */
    const char* str_queue = NULL;
    char str_num[10];
    switch( queue_id ) {
    case OFPQ_ALL:
        str_queue = "All queues (all queues configured on a physical port)";
        break;

    default:
        str_queue = str_num;
        snprintf(str_num, 10, "%u", queue_id);
    }

    add_child_str(tree, hf, tvb, offset, 4, str_queue);
}

static void dissect_port_mod(proto_tree* tree, proto_item* item, tvbuff_t *tvb, packet_info *pinfo, guint32 *offset)
{
    proto_item *config_item;
    proto_tree *config_tree;
    proto_item *mask_item;
    proto_tree *mask_tree;
    proto_item *advertise_item;
    proto_tree *advertise_tree;

    int i;
    dissect_port( tree, ofp_port_mod_port_no, tvb, offset );
    add_child( tree, ofp_port_mod_hw_addr, tvb, offset, OFP_ETH_ALEN );

    /* config */
    config_item = proto_tree_add_item(tree, ofp_port_mod_config_hdr, tvb, *offset, 4, FALSE);
    config_tree = proto_item_add_subtree(config_item, ett_ofp_port_mod_config_hdr);
    for(i=0; i<NUM_PORT_CONFIG_FLAGS; i++) {
        add_child_const(config_tree, ofp_port_mod_config[i], tvb, *offset, 4);
    }
    *offset += 4;

    /* mask */
    mask_item = proto_tree_add_item(tree, ofp_port_mod_mask_hdr, tvb, *offset, 4, FALSE);
    mask_tree = proto_item_add_subtree(mask_item, ett_ofp_port_mod_mask_hdr);
    for(i=0; i<NUM_PORT_CONFIG_FLAGS; i++) {
        add_child_const(mask_tree, ofp_port_mod_mask[i], tvb, *offset, 4);
    }
    *offset += 4;

    /* advertise */
    advertise_item = proto_tree_add_item(tree, ofp_port_mod_advertise_hdr, tvb, *offset, 4, FALSE);
    advertise_tree = proto_item_add_subtree(advertise_item, ett_ofp_port_mod_advertise_hdr);
    for(i=0; i<NUM_PORT_FEATURES_FLAGS; i++) {
        add_child_const(advertise_tree, ofp_port_mod_advertise[i], tvb, *offset, 4);
    }
    *offset += 4;

    /* pad */
    dissect_pad(tree, offset, 4);
}

static void dissect_wildcards(proto_tree* match_tree, proto_item* match_item, tvbuff_t *tvb, packet_info *pinfo, guint32 *offset, gint wildcard_list[])
{
    proto_item *wild_item = proto_tree_add_item(match_tree, ofp_match_wildcards_hdr, tvb, *offset, 4, FALSE);
    proto_tree *wild_tree = proto_item_add_subtree(wild_item, ett_ofp_match_wildcards_hdr);

    /* add wildcard subtree */
    int i;
    for(i=0; i<NUM_WILDCARDS; i++)
        add_child_const(wild_tree, wildcard_list[i], tvb, *offset, 4 );
    *offset += 4;
}

static void dissect_dl_type(proto_tree* tree, gint hf, tvbuff_t *tvb, guint32 *offset) {
    /* get the datalink type */
    guint16 dl_type = tvb_get_ntohs( tvb, *offset );

	const char* description = match_strval(dl_type, etype_vals);

    /* put the string-representation in the GUI tree */
    proto_tree_add_uint_format(tree, hf, tvb, *offset, 2, dl_type,
            "Ethernet Type: %s (0x%04x)", description, dl_type);

    *offset += 2;
}

static void dissect_nw_proto(proto_tree* tree, gint hf, tvbuff_t *tvb, guint32 *offset) {
    /* get the network protocol */
    guint8 nw_proto = tvb_get_guint8( tvb, *offset );

    /* put the string-representation in the GUI tree */
    proto_tree_add_uint_format(tree, hf, tvb, *offset, 1, nw_proto,
            "Protocol: %s (0x%02x)", ipprotostr(nw_proto), nw_proto);

    *offset += 1;
}

static void dissect_tp_port(proto_tree* tree, gint hf, tvbuff_t *tvb, guint32 *offset) {
    /* get the transport port */
    guint16 port = tvb_get_ntohs( tvb, *offset );

    /* Get the header field info corresponding to the field */
    header_field_info *hfinfo = proto_registrar_get_nth(hf);

    /* put the string-representation in the GUI tree */
    proto_tree_add_uint_format(tree, hf, tvb, *offset, 2, port,
            "%s: %s (%u)", hfinfo->name, get_tcp_port(port), port);

    *offset += 2;
}

/* Based on: dissect_icmp from wireshark: epan/dissectors/packet-ip.c */
static void dissect_icmp_type_code_match(proto_tree* tree, tvbuff_t *tvb, guint32 *offset, gint show_type, gint show_code)
{
    guint16    icmp_type;
    guint16    icmp_code;
    const gchar *type_str, *code_str;

    type_str="";
    code_str="";

    /* Get the ICMP type/code */
    icmp_type = tvb_get_ntohs(tvb, *offset);
    icmp_code = tvb_get_ntohs(tvb, *offset + 2);

    /* Get string representations of the ICMP types/codes */
    switch (icmp_type) {
        case ICMP_ECHOREPLY:
            type_str="Echo (ping) reply";
            break;
        case ICMP_UNREACH:
            type_str="Destination unreachable";
            if (icmp_code < N_UNREACH) {
                code_str = unreach_str[icmp_code];
            } else {
                code_str = "Unknown - error?";
            }
            break;
        case ICMP_SOURCEQUENCH:
            type_str="Source quench (flow control)";
            break;
        case ICMP_REDIRECT:
            type_str="Redirect";
            if (icmp_code < N_REDIRECT) {
                code_str = redir_str[icmp_code];
            } else {
                code_str = "Unknown - error?";
            }
            break;
        case ICMP_ECHO:
            type_str="Echo (ping) request";
            break;
        case ICMP_RTRADVERT:
            switch (icmp_code) {
            case 0: /* Mobile-Ip */
            case 16: /* Mobile-Ip */
                type_str="Mobile IP Advertisement";
                break;
            default:
                type_str="Router advertisement";
                break;
            } /* switch icmp_code */
            break;
        case ICMP_RTRSOLICIT:
            type_str="Router solicitation";
            break;
        case ICMP_TIMXCEED:
            type_str="Time-to-live exceeded";
            if (icmp_code < N_TIMXCEED) {
                code_str = ttl_str[icmp_code];
            } else {
                code_str = "Unknown - error?";
            }
            break;
        case ICMP_PARAMPROB:
            type_str="Parameter problem";
            if (icmp_code < N_PARAMPROB) {
                code_str = par_str[icmp_code];
            } else {
                code_str = "Unknown - error?";
            }
            break;
        case ICMP_TSTAMP:
            type_str="Timestamp request";
            break;
        case ICMP_TSTAMPREPLY:
            type_str="Timestamp reply";
            break;
        case ICMP_IREQ:
            type_str="Information request";
            break;
        case ICMP_IREQREPLY:
            type_str="Information reply";
            break;
        case ICMP_MASKREQ:
            type_str="Address mask request";
            break;
        case ICMP_MASKREPLY:
            type_str="Address mask reply";
            break;
        default:
            type_str="Unknown ICMP (obsolete or malformed?)";
            break;
    }

    if (show_type)
        proto_tree_add_uint_format(tree, ofp_match_icmp_type, tvb, *offset, 2,
                   icmp_type,
                   "ICMP Type: %u (%s)",
                   icmp_type, type_str);
    if (show_code)
        proto_tree_add_uint_format(tree, ofp_match_icmp_code, tvb, *offset, 2,
                   icmp_code,
                   "ICMP Code: %u (%s)",
                   icmp_code, code_str);

    *offset += 4;
}

static void dissect_match(proto_tree* tree, proto_item* item, tvbuff_t *tvb, packet_info *pinfo, guint32 *offset)
{
    proto_item *match_item = proto_tree_add_item(tree, ofp_match, tvb, *offset, sizeof(struct ofp_match), FALSE);
    proto_tree *match_tree = proto_item_add_subtree(match_item, ett_ofp_match);

    /* save wildcards field for later */
    guint32 wildcards = tvb_get_ntohl( tvb, *offset );

    dissect_wildcards(match_tree, match_item, tvb, pinfo, offset, ofp_match_wildcards);

    /* show only items whose corresponding wildcard bit is not set */
    if( ~wildcards & OFPFW_IN_PORT )
        dissect_port(match_tree, ofp_match_in_port, tvb, offset);
    else
        *offset += 2;

    if( ~wildcards & OFPFW_DL_SRC )
        add_child(match_tree, ofp_match_dl_src, tvb, offset, 6);
    else
        *offset += 6;

    if( ~wildcards & OFPFW_DL_DST )
        add_child(match_tree, ofp_match_dl_dst, tvb, offset, 6);
    else
        *offset += 6;

    if( ~wildcards & OFPFW_DL_VLAN )
        add_child(match_tree, ofp_match_dl_vlan, tvb, offset, 2);
    else
        *offset += 2;

    if( ~wildcards & OFPFW_DL_VLAN_PCP )
        add_child(match_tree, ofp_match_dl_vlan_pcp, tvb, offset, 1);
    else
        *offset += 1;

    dissect_pad(match_tree, offset, 1);

    /* Save DL type for later */
    guint16 dl_type = tvb_get_ntohs( tvb, *offset);

    if( ~wildcards & OFPFW_DL_TYPE )
        dissect_dl_type(match_tree, ofp_match_dl_type, tvb, offset);
    else
        *offset += 2;

    if( ~wildcards & OFPFW_NW_TOS )
        add_child(match_tree, ofp_match_nw_tos, tvb, offset, 1);
    else
        *offset += 1;

    /* Save NW proto for later */
    guint8 nw_proto = tvb_get_guint8( tvb, *offset);

    /* Custom handling for ARP packets vs non-ARP packets */
    if ( dl_type == ETHERTYPE_ARP )
        add_child(match_tree, ofp_match_arp_opcode, tvb, offset, 1);
    else if( ~wildcards & OFPFW_NW_PROTO )
        dissect_nw_proto(match_tree, ofp_match_nw_proto, tvb, offset);
    else
        *offset += 1;

    dissect_pad(match_tree, offset, 2);

    if( ~wildcards & OFPFW_NW_SRC_MASK )
        add_child(match_tree, ofp_match_nw_src, tvb, offset, 4);
    else
        *offset += 4;

    if( ~wildcards & OFPFW_NW_DST_MASK )
        add_child(match_tree, ofp_match_nw_dst, tvb, offset, 4);
    else
        *offset += 4;

    /* Display either ICMP type/code or TCP/UDP ports */
    if( dl_type == ETHERTYPE_IP && nw_proto == IP_PROTO_ICMP) {
        dissect_icmp_type_code_match(match_tree, tvb, offset,
                ~wildcards & OFPFW_TP_SRC,
                ~wildcards & OFPFW_TP_DST );
    }
    else {
        if( ~wildcards & OFPFW_TP_SRC )
            dissect_tp_port(match_tree, ofp_match_tp_src, tvb, offset);
        else
            *offset += 2;

        if( ~wildcards & OFPFW_TP_DST )
            dissect_tp_port(match_tree, ofp_match_tp_dst, tvb, offset);
        else
            *offset += 2;
    }
}

static void dissect_action_output(proto_tree* tree, tvbuff_t *tvb, guint32 *offset)
{
    /* add the output port */
    dissect_port( tree, ofp_action_output_port, tvb, offset );

    /* determine the maximum number of bytes to send (0 =>  no limit) */
    guint16 max_len = tvb_get_ntohs( tvb, *offset );
    char str[11];
    snprintf( str, 11, "%u", max_len );
    add_child_str( tree, ofp_action_output_max_len, tvb, offset, 2, str );
}

static void dissect_action_enqueue(proto_tree* tree, tvbuff_t *tvb, guint32 *offset)
{
    /* add the output port */
    dissect_port( tree, ofp_action_enqueue_port_no, tvb, offset );
    dissect_pad(tree, offset, 6);
    dissect_queue_id(tree, ofp_action_enqueue_queue_id, tvb, offset);
}


/** returns the number of bytes dissected (-1 if an unknown action type is
 *  encountered; and 8/16 for all other actions as of 0x96) */
static gint dissect_action(proto_tree* tree, proto_item* item, tvbuff_t *tvb, packet_info *pinfo, guint32 *offset)
{
    guint32 offset_start = *offset;
    guint16 type = tvb_get_ntohs( tvb, *offset );
	guint16 len = tvb_get_ntohs( tvb, *offset + 2);
	
    proto_item *action_item = proto_tree_add_item(tree, ofp_action, tvb, *offset, len, FALSE);
    proto_tree *action_tree = proto_item_add_subtree(action_item, ett_ofp_action);

    if (!(len == 8 || len == 16)) {
        add_child_str(action_tree, ofp_action_unknown, tvb, offset, len, "Invalid Action Length");
        return -1;
    }

    add_child( action_tree, ofp_action_type, tvb, offset, 2 );
    add_child( action_tree, ofp_action_len, tvb, offset, 2 );

    switch( type ) {
    case OFPAT_OUTPUT:
        dissect_action_output(action_tree, tvb, offset);
        break;

    case OFPAT_SET_VLAN_VID:
        add_child( action_tree, ofp_action_vlan_vid, tvb, offset, 2 );
        dissect_pad(action_tree, offset, 2);
        break;
    	
    case OFPAT_SET_VLAN_PCP:
        add_child( action_tree, ofp_action_vlan_pcp, tvb, offset, 1 );
        dissect_pad(action_tree, offset, 3);
        break;

    case OFPAT_STRIP_VLAN:
        add_child( action_tree, ofp_action_unknown, tvb, offset, 0 );
    	dissect_pad(action_tree, offset, 4);    	
        break;

    case OFPAT_SET_DL_SRC:
    case OFPAT_SET_DL_DST:
        add_child(action_tree, ofp_action_dl_addr, tvb, offset, 6 );
    	dissect_pad(action_tree, offset, 6);
        break;

    case OFPAT_SET_NW_SRC:
    case OFPAT_SET_NW_DST:
        add_child( action_tree, ofp_action_nw_addr, tvb, offset, 4 );
        break;

	case OFPAT_SET_NW_TOS:
	  add_child( action_tree, ofp_action_nw_tos, tvb, offset, 1);
	  dissect_pad(action_tree, offset, 3);
	  break;

    case OFPAT_SET_TP_SRC:
    case OFPAT_SET_TP_DST:
        add_child( action_tree, ofp_action_tp_port, tvb, offset, 2 );
        dissect_pad(action_tree, offset, 2);
        break;

    case OFPAT_ENQUEUE:
        dissect_action_enqueue(action_tree, tvb, offset);
        break;

    default:
        add_child( action_tree, ofp_action_unknown, tvb, offset, 0 );
        return -1;
    }

    /* return the number of bytes which were consumed */
    return *offset - offset_start;
}

static void dissect_action_array(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint len, guint offset)
{
    guint total_len = len - offset;

    proto_item* action_item = proto_tree_add_item(tree, ofp_action_output, tvb, offset, total_len, FALSE);
    proto_tree* action_tree = proto_item_add_subtree(action_item, ett_ofp_action_output);

    if( total_len == 0 )
        add_child_str(action_tree, ofp_action_warn, tvb, &offset, 0, "No actions were specified");
    else if( offset > len ) {
        /* not enough bytes => wireshark will already have reported the error */
    }
    else {
        guint offset_action_start = offset;
        guint num_actions = 0;
        while( total_len > 0 ) {
            num_actions += 1;
            int ret = dissect_action(action_tree, action_item, tvb, pinfo, &offset);
            if( ret < 0 )
                break; /* stop if we run into an action we couldn't dissect */
            else
                total_len -= ret;
        }
        proto_tree_add_uint(action_tree, ofp_action_num, tvb, offset_action_start, 0, num_actions);
    }
}

static void dissect_property_min(proto_tree* tree, tvbuff_t *tvb, guint32 *offset)
{
    add_child(tree, ofp_packet_queue_property_rate, tvb, offset, 2);
    dissect_pad(tree, offset, 6);
}

static gint32 dissect_property(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, guint32 *offset)
{
    guint32 offset_start = *offset;
    guint16 type = tvb_get_ntohs(tvb, *offset);
    guint16 len = tvb_get_ntohs(tvb, *offset + 2);

    proto_item *property_item = proto_tree_add_item(tree, ofp_packet_queue_property, tvb, *offset, len, FALSE);
    proto_tree *property_tree = proto_item_add_subtree(property_item, ett_ofp_packet_queue_property);

    add_child(property_tree, ofp_packet_queue_property_type, tvb, offset, 2);
    add_child(property_tree, ofp_packet_queue_property_len, tvb, offset, 2);
    dissect_pad(tree, offset, 4);

    switch( type ) {
    case OFPQT_MIN_RATE:
        dissect_property_min(property_tree, tvb, offset);
        break;
    default:
        add_child(property_tree, ofp_packet_queue_property_unknown, tvb, offset, 0);
        return -1;
    }

    return *offset - offset_start;
}

/* returns the number of bytes dissected ( -1 if unknown propery is encountered */
static void dissect_property_array(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint len, guint32 *offset)
{
    guint total_len  = len;

    proto_item *property_item = proto_tree_add_item(tree, ofp_packet_queue_properties_hdr, tvb, *offset, total_len, FALSE);
    proto_tree *property_tree = proto_item_add_subtree(property_item, ett_ofp_packet_queue_properties_hdr);

    if( total_len == 0 ) {
        add_child_str(property_tree, ofp_packet_queue_property_warn, tvb, offset, 0, "No properties were specified");
    }
    else {
        guint32 offset_property_start = *offset;
        guint num_properties = 0;
        while( total_len > 0 ) {
            num_properties += 1;
            int ret = dissect_property(property_tree, tvb, pinfo, offset);
            if( ret < 0 ) {
                break; /* stop if we run into a property we couldn't dissect */
            }
            else
                total_len -= ret;
        }
        proto_tree_add_uint(property_tree, ofp_packet_queue_properties_num, tvb, offset_property_start, 0, num_properties);
    }
}

/** returns the number of bytes dissected (-1 if an unknown property is
 *  encountered; */
static gint dissect_queue(proto_tree* tree, tvbuff_t *tvb, packet_info *pinfo, guint32 *offset)
{
    guint32 offset_start = *offset;
    guint16 len = tvb_get_ntohs( tvb, *offset + 4);

    proto_item *queue_item = proto_tree_add_item(tree, ofp_packet_queue, tvb, *offset, len, FALSE);
    proto_tree *queue_tree = proto_item_add_subtree(queue_item, ett_ofp_packet_queue);

    //    add_child( queue_tree, ofp_packet_queue_queue_id, tvb, offset, 4 );
    dissect_queue_id(queue_tree, ofp_packet_queue_queue_id, tvb, offset);
    add_child( queue_tree, ofp_packet_queue_len, tvb, offset, 2 );
    dissect_pad( queue_tree, offset, 2);

    dissect_property_array(tvb, pinfo, queue_tree, len - (*offset - offset_start), offset);
    return *offset - offset_start;

}

static void dissect_queue_array(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint len, guint32 *offset)
{
    guint total_len = len - *offset;

    proto_item *queue_item = proto_tree_add_item(tree, ofp_queue_get_config_reply_queues_hdr, tvb, *offset, total_len, FALSE);
    proto_tree *queue_tree = proto_item_add_subtree(queue_item, ett_ofp_queue_get_config_reply_queues_hdr);

    if( total_len == 0 ) {
        add_child_str(queue_tree, ofp_packet_queue_warn, tvb, offset, 0, "No queues were specified");
    }
    else if( *offset > len ) {
        /* not enough bytes => wireshark will already have reported the error */
    }
    else {
        guint offset_queue_start = *offset;
        guint num_queues = 0;
        while( total_len > 0 ) {
            num_queues += 1;
            int ret = dissect_queue(queue_tree, tvb, pinfo, offset);
            if( ret < 0 )
                break; /* stop if we run into an action we couldn't dissect */
            else
                total_len -= ret;
        }
        proto_tree_add_uint(queue_tree, ofp_queue_get_config_reply_queues_num, tvb, offset_queue_start, 0, num_queues);
    }
}


static void dissect_capability_array(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint field_size) {
    proto_item *sf_cap_item = proto_tree_add_item(tree, ofp_switch_features_capabilities_hdr, tvb, offset, field_size, FALSE);
    proto_tree *sf_cap_tree = proto_item_add_subtree(sf_cap_item, ett_ofp_switch_features_capabilities_hdr);
    gint i;
    for(i=0; i<NUM_CAPABILITIES_FLAGS; i++)
        add_child_const(sf_cap_tree, ofp_switch_features_capabilities[i], tvb, offset, field_size);
}

static void dissect_switch_config_flags(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset) {
    proto_item *sf_pc_item = proto_tree_add_item(tree, ofp_switch_config_flags_hdr, tvb, *offset, 2, FALSE);
    proto_tree *sf_pc_tree = proto_item_add_subtree(sf_pc_item, ett_ofp_switch_config_flags_hdr);

    add_child_const(sf_pc_tree, ofp_switch_config_flags_ip_frag, tvb, *offset, 2);

    *offset += 2;

}

static void dissect_switch_features_actions(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint field_size) {
    proto_item *sf_act_item = proto_tree_add_item(tree, ofp_switch_features_actions_hdr, tvb, offset, field_size, FALSE);
    proto_tree *sf_act_tree = proto_item_add_subtree(sf_act_item, ett_ofp_switch_features_actions_hdr);
    gint i;
    for(i=0; i<NUM_ACTIONS_FLAGS; i++)
        add_child_const(sf_act_tree, ofp_switch_features_actions[i], tvb, offset, field_size);
}

static void dissect_ethernet(tvbuff_t *next_tvb, packet_info *pinfo, proto_tree *data_tree) {
    /* add seperators to existing column strings */
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
        col_append_str( pinfo->cinfo, COL_PROTOCOL, "+" );

    if(check_col(pinfo->cinfo,COL_INFO))
        col_append_str( pinfo->cinfo, COL_INFO, " => " );

    /* set up fences so ethernet dissectors only appends to our column info */
    col_set_fence(pinfo->cinfo, COL_PROTOCOL);
    col_set_fence(pinfo->cinfo, COL_INFO);

    /* continue the dissection with the ethernet dissector */
    call_dissector(data_ethernet, next_tvb, pinfo, data_tree);
}

static void dissect_error_code(proto_tree* tree, gint hf, tvbuff_t *tvb, guint32 *offset, guint16 err_type) {
    guint16 err_code;
    guint8  valid;
    const gchar *code_str;

    err_code = tvb_get_ntohs(tvb, *offset);
    code_str = "";
    valid = TRUE;

    switch (err_type) {
        case OFPET_HELLO_FAILED:
            if (err_code < N_HELLOFAILED) {
                code_str = hello_failed_err_str[err_code];
            } else {
                code_str = "Unknown - error?";
            }
            break;
        case OFPET_BAD_REQUEST:
            if (err_code < N_BADREQUEST) {
                code_str = bad_request_err_str[err_code];
            } else {
                code_str = "Unknown - error?";
            }
            break;
        case OFPET_BAD_ACTION:
            if (err_code < N_BADACTION) {
                code_str = bad_action_err_str[err_code];
            } else {
                code_str = "Unknown - error?";
            }
            break;
        case OFPET_FLOW_MOD_FAILED:
            if (err_code < N_FLOWMODFAILED) {
                code_str = flow_mod_failed_err_str[err_code];
            } else {
                code_str = "Unknown - error?";
            }
            break;
        case OFPET_PORT_MOD_FAILED:
            if (err_code < N_PORTMODFAILED) {
                code_str = port_mod_failed_err_str[err_code];
            } else {
                code_str = "Unknown - error?";
            }
            break;
        case OFPET_QUEUE_OP_FAILED:
            if (err_code < N_QUEUEOPFAILED) {
                code_str = queue_op_failed_err_str[err_code];
            } else {
                code_str = "Unknown - error?";
            }
            break;

        default:
            valid = FALSE;
            break;
    }

    if (valid)
        proto_tree_add_uint_format(tree, hf, tvb, *offset, 2,
                   err_code,
                   "Code: %s (%u)",
                   code_str, err_code);
    else
        proto_tree_add_item(tree, hf, tvb, *offset, 2, FALSE);

    *offset += 2;
}

static void dissect_flow_mod_flags(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint *offset) {
    proto_item *fm_flags_item = proto_tree_add_item(tree, ofp_switch_config_flags_hdr, tvb, *offset, 2, FALSE);
    proto_tree *fm_flags_tree = proto_item_add_subtree(fm_flags_item, ett_ofp_flow_mod_flags_hdr);
    int i;

  for (i = 0; i < NUM_FLOW_MOD_FLAGS; i++)
    add_child_const(fm_flags_tree, ofp_flow_mod_flags[i], tvb, *offset, 2);

    *offset += 2;
}


static void dissect_openflow_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
#   define STR_LEN 1024
    char str[STR_LEN];

    /* display our protocol text if the protocol column is visible */
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
        col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_OPENFLOW);

    /* Clear out stuff in the info column */
    if(check_col(pinfo->cinfo,COL_INFO))
        col_clear(pinfo->cinfo,COL_INFO);

    /* get some of the header fields' values for later use */
    guint8  ver  = tvb_get_guint8( tvb, 0 );
    guint8  type = tvb_get_guint8( tvb, 1 );
    guint16 len  = tvb_get_ntohs(  tvb, 2 );

    /* add a warning if the version is what the plugin was written to handle */
    guint8 ver_warning = 0;
    if( ver < DISSECTOR_OPENFLOW_MIN_VERSION || ver > DISSECTOR_OPENFLOW_MAX_VERSION || ver >= DISSECTOR_OPENFLOW_VERSION_DRAFT_THRESHOLD ) {
        if( ver>=DISSECTOR_OPENFLOW_VERSION_DRAFT_THRESHOLD && ver<=DISSECTOR_OPENFLOW_MAX_VERSION )
            snprintf( str, STR_LEN, "DRAFT Dissector written for this OpenFlow version v0x%0X", ver );
        else {
            ver_warning = 1;
            if( DISSECTOR_OPENFLOW_MIN_VERSION == DISSECTOR_OPENFLOW_MAX_VERSION )
                snprintf( str, STR_LEN,
                          "Dissector written for OpenFlow v0x%0X (differs from this packet's version v0x%0X)",
                          DISSECTOR_OPENFLOW_MIN_VERSION, ver );
            else
                snprintf( str, STR_LEN,
                          "Dissector written for OpenFlow v0x%0X-v0x%0X (differs from this packet's version v0x%0X)",
                          DISSECTOR_OPENFLOW_MIN_VERSION, DISSECTOR_OPENFLOW_MAX_VERSION, ver );
        }
    }

    /* clarify protocol name display with version, length, and type information */
    if (check_col(pinfo->cinfo, COL_INFO)) {
        /* special handling so we can put buffer IDs in the description */
        char str_extra[32];
        str_extra[0] = '\0';
        if( type==OFPT_PACKET_IN || type==OFPT_PACKET_OUT ) {
            guint32 bid = tvb_get_ntohl(tvb, sizeof(struct ofp_header));
            if( bid != 0xFFFFFFFF )
                snprintf(str_extra, 32, "(BufID=%u) ", bid);
        }

        if( ver_warning )
            col_add_fstr( pinfo->cinfo, COL_INFO, "%s %s(%uB) Ver Warning!", ofp_type_to_string(type), str_extra, len );
        else
            col_add_fstr( pinfo->cinfo, COL_INFO, "%s %s(%uB)", ofp_type_to_string(type), str_extra, len );
    }

    if (tree) { /* we are being asked for details */
        proto_item *item        = NULL;
        proto_item *sub_item    = NULL;
        proto_tree *ofp_tree    = NULL;
        proto_tree *header_tree = NULL;
        guint32 offset = 0;
        proto_item *type_item  = NULL;
        proto_tree *type_tree  = NULL;

        /* consume the entire tvb for the openflow packet, and add it to the tree */
        item = proto_tree_add_item(tree, proto_openflow, tvb, 0, -1, FALSE);
        ofp_tree = proto_item_add_subtree(item, ett_ofp);

        /* put the header in its own node as a child of the openflow node */
        sub_item = proto_tree_add_item( ofp_tree, ofp_header, tvb, offset, 8, FALSE );
        header_tree = proto_item_add_subtree(sub_item, ett_ofp_header);

        if( ver_warning )
            add_child_str( header_tree, ofp_header_warn_ver, tvb, &offset, 0, str );

        /* add the headers field as children of the header node */
        add_child( header_tree, ofp_header_version, tvb, &offset, 1 );
        add_child( header_tree, ofp_header_type,    tvb, &offset, 1 );
        add_child( header_tree, ofp_header_length,  tvb, &offset, 2 );
        add_child( header_tree, ofp_header_xid,     tvb, &offset, 4 );

        switch( type ) {

        case OFPT_HELLO: {
            /* nothing else in this packet type */
            break;
        }

        case OFPT_BARRIER_REQUEST:
        case OFPT_BARRIER_REPLY:
            /* nothing else in this packet type */
            break;

        case OFPT_ERROR: {
            type_item = proto_tree_add_item(ofp_tree, ofp_error_msg, tvb, offset, -1, FALSE);
            type_tree = proto_item_add_subtree(type_item, ett_ofp_error_msg);

            /* Extract the type for use later */
            guint16 type = tvb_get_ntohs(tvb, offset);

            add_child(type_tree, ofp_error_msg_type, tvb, &offset, 2);
            dissect_error_code(type_tree, ofp_error_msg_code, tvb, &offset, type);

            if (type == OFPET_HELLO_FAILED)
                add_child(type_tree, ofp_error_msg_data_str, tvb, &offset, len - offset);
            else if (type == OFPET_BAD_REQUEST ||
                     type == OFPET_BAD_ACTION ||
                     type == OFPET_FLOW_MOD_FAILED) {
                /* Dissect the data as an OpenFlow packet */
                proto_item *data_item = proto_tree_add_item(type_tree, ofp_error_msg_data, tvb, offset, -1, FALSE);
                proto_tree *data_tree = proto_item_add_subtree(data_item, ett_ofp_error_msg_data);
                tvbuff_t *next_tvb = tvb_new_subset(tvb, offset, -1, len - offset);

                /* Temporarily disable writing */
                gboolean writeable = col_get_writable(pinfo->cinfo);
                col_set_writable( pinfo->cinfo, FALSE);

                /* Finally do the dissection */
                dissect_openflow_message(next_tvb, pinfo, data_tree);

                col_set_writable( pinfo->cinfo, writeable);

                offset += (len - offset);
            }
            else
                add_child(type_tree, ofp_error_msg_data, tvb, &offset, len - offset);
            break;
        }

        case OFPT_ECHO_REQUEST:
        case OFPT_ECHO_REPLY: {
            if (len - offset > 0)
                add_child(tree, ofp_echo, tvb, &offset, len - offset);
            break;
        }
        	 	
        case OFPT_VENDOR: {
            if (len - offset > 0) {
                add_child(tree, ofp_vendor, tvb, &offset, len - offset);
            }
            break;        	
        }

        case OFPT_FEATURES_REQUEST:
            /* nothing else in this packet type */
            break;

        case OFPT_FEATURES_REPLY: {

            proto_item *sf_port_item = NULL;
            proto_tree *sf_port_tree = NULL;
            guint num_ports;
            gint sz;

            type_item = proto_tree_add_item(ofp_tree, ofp_switch_features, tvb, offset, -1, FALSE);
            //break;
            type_tree = proto_item_add_subtree(type_item, ett_ofp_switch_features);

            /* fields we'll put directly in the subtree */

            add_child(type_tree, ofp_switch_features_datapath_id, tvb, &offset, 8);

            add_child(type_tree, ofp_switch_features_n_buffers, tvb, &offset, 4);
            add_child(type_tree, ofp_switch_features_n_tables, tvb, &offset, 1);
            dissect_pad(type_tree, &offset, 3);


            /* capabilities */
            dissect_capability_array(tvb, pinfo, type_tree, offset, 4);
            offset += 4;

            /* actions */
            dissect_switch_features_actions(tvb, pinfo, type_tree, offset, 4);
            offset += 4;

            /* handle ports */
            sf_port_item = proto_tree_add_item(type_tree, ofp_switch_features_ports_hdr, tvb, offset, -1, FALSE);
            sf_port_tree = proto_item_add_subtree(sf_port_item, ett_ofp_switch_features_ports_hdr);
            sz = len - sizeof(struct ofp_switch_features);

            if( sz > 0 ) {
                num_ports = sz / sizeof(struct ofp_phy_port); /* number of ports */
                proto_tree_add_uint(sf_port_tree, ofp_switch_features_ports_num, tvb, offset, num_ports*sizeof(struct ofp_phy_port), num_ports);

                dissect_phy_ports(sf_port_tree, sf_port_item, tvb, pinfo, &offset, num_ports);
                if( num_ports * sizeof(struct ofp_phy_port) < sz ) {
                    snprintf(str, STR_LEN, "%uB were leftover at end of packet", sz - num_ports*sizeof(struct ofp_phy_port));
                    add_child_str(sf_port_tree, ofp_switch_features_ports_warn, tvb, &offset, 0, str);
                }
            }
            else if( sz < 0 ) {
                /* not enough bytes => wireshark will already have reported the error */
            }
            else {
                snprintf(str, STR_LEN, "No ports were specified");
                add_child_str(sf_port_tree, ofp_switch_features_ports_warn, tvb, &offset, 0, str);
            }
            break;
        }

        case OFPT_GET_CONFIG_REQUEST:
            /* nothing else in this packet type */
            break;

        case OFPT_GET_CONFIG_REPLY:
        case OFPT_SET_CONFIG: {
            type_item = proto_tree_add_item(ofp_tree, ofp_switch_config, tvb, offset, -1, FALSE);
            type_tree = proto_item_add_subtree(type_item, ett_ofp_switch_config);
            dissect_switch_config_flags(tvb, pinfo, type_tree, &offset);
            add_child(type_tree, ofp_switch_config_miss_send_len, tvb, &offset, 2);
            break;
        }

        case OFPT_QUEUE_GET_CONFIG_REQUEST: {
            type_item = proto_tree_add_item(ofp_tree, ofp_queue_get_config_request, tvb, offset, -1, FALSE);
            type_tree = proto_item_add_subtree(type_item, ett_ofp_queue_get_config_request);
            dissect_port(type_tree, ofp_queue_get_config_request_port_no, tvb, &offset);
            dissect_pad(type_tree, &offset, 2);
            break;
        }

        case OFPT_QUEUE_GET_CONFIG_REPLY: {
            type_item = proto_tree_add_item(ofp_tree, ofp_queue_get_config_reply, tvb, offset, -1, FALSE);
            type_tree = proto_item_add_subtree(type_item, ett_ofp_queue_get_config_reply);

            dissect_port(type_tree, ofp_queue_get_config_reply_port_no, tvb, &offset);
            dissect_pad(type_tree, &offset, 6);

            /* handle queues */
            dissect_queue_array(tvb, pinfo, type_tree, len, &offset);
            break;
        }

        case OFPT_PACKET_IN: {
            type_item = proto_tree_add_item(ofp_tree, ofp_packet_in, tvb, offset, -1, FALSE);
            type_tree = proto_item_add_subtree(type_item, ett_ofp_packet_in);

            add_child(type_tree, ofp_packet_in_buffer_id, tvb, &offset, 4);

            /* explicitly pull out the length so we can use it to determine data's size */
            guint16 total_len = tvb_get_ntohs( tvb, offset );
            proto_tree_add_uint(type_tree, ofp_packet_in_total_len, tvb, offset, 2, total_len);
            offset += 2;

            add_child(type_tree, ofp_packet_in_in_port, tvb, &offset, 2);
            add_child(type_tree, ofp_packet_in_reason, tvb, &offset, 1);
            dissect_pad(type_tree, &offset, 1);

            if (len > sizeof(struct ofp_packet_in)) {
                /* continue the dissection with the Ethernet dissector */
                if (data_ethernet) {
                    proto_item *data_item = proto_tree_add_item(type_tree, ofp_packet_in_data_hdr, tvb, offset, -1, FALSE);
                    proto_tree *data_tree = proto_item_add_subtree(data_item, ett_ofp_packet_in_data_hdr);
                    tvbuff_t *next_tvb = tvb_new_subset(tvb, offset, -1, total_len);
                    dissect_ethernet(next_tvb, pinfo, data_tree);
                } else {
                    /* if we couldn't load the ethernet dissector, just display the bytes */
                    add_child(type_tree, ofp_packet_in_data_hdr, tvb, &offset, total_len);
                }
            }
            break;
        }

        case OFPT_FLOW_REMOVED: {
            type_item = proto_tree_add_item(ofp_tree, ofp_flow_removed, tvb, offset, -1, FALSE);
            type_tree = proto_item_add_subtree(type_item, ett_ofp_flow_removed);

            dissect_match(type_tree, type_item, tvb, pinfo, &offset);
            add_child(type_tree, ofp_flow_removed_cookie, tvb, &offset, 8);
            add_child(type_tree, ofp_flow_removed_priority, tvb, &offset, 2);
            add_child(type_tree, ofp_flow_removed_reason, tvb, &offset, 1);
            dissect_pad(type_tree, &offset, 1);
            add_child(type_tree, ofp_flow_removed_duration_sec, tvb, &offset, 4);
            add_child(type_tree, ofp_flow_removed_duration_nsec, tvb, &offset, 4);
            add_child(type_tree, ofp_flow_removed_idle_timeout, tvb, &offset, 2);
            dissect_pad(type_tree, &offset, 2);
            add_child(type_tree, ofp_flow_removed_packet_count, tvb, &offset, 8);
            add_child(type_tree, ofp_flow_removed_byte_count, tvb, &offset, 8);
            break;
        }

        case OFPT_PORT_STATUS: {
            type_item = proto_tree_add_item(ofp_tree, ofp_port_status, tvb, offset, -1, FALSE);
            type_tree = proto_item_add_subtree(type_item, ett_ofp_port_status);

            add_child(type_tree, ofp_port_status_reason, tvb, &offset, 1);
            dissect_pad(type_tree, &offset, 7);
            dissect_phy_ports(type_tree, type_item, tvb, pinfo, &offset, 1);
            break;
        }

        case OFPT_PACKET_OUT: {
            type_item = proto_tree_add_item(ofp_tree, ofp_packet_out, tvb, offset, -1, FALSE);
            type_tree = proto_item_add_subtree(type_item, ett_ofp_packet_out);

            /* get buffer_id value for later use */
            guint32 buffer_id = tvb_get_ntohl( tvb, offset );

            if( buffer_id == 0xFFFFFFFF )
                add_child_str(type_tree, ofp_packet_out_buffer_id, tvb, &offset, 4, "None");
            else {
                snprintf(str, STR_LEN, "%u", buffer_id);
                add_child_str(type_tree, ofp_packet_out_buffer_id, tvb, &offset, 4, str);
            }

            /* display in port */
            // FIXME: bug in dissect_port for latest version
            dissect_port(type_tree, ofp_packet_out_in_port, tvb, &offset);

            /* pull out actions len */
            guint16 actions_len = tvb_get_ntohs( tvb, offset);
            add_child(type_tree, ofp_packet_out_actions_len, tvb, &offset, 2);

            /* dissect action array; will handle no-action case */
            dissect_action_array(tvb, pinfo, type_tree, offset + actions_len, offset);
            offset += actions_len;

            /* if buffer id == -1, then display the provided packet */
            if( buffer_id == -1 ) {
                /* continue the dissection with the Ethernet dissector */
                guint total_len = len - offset;
                if( data_ethernet ) {
                    proto_item *data_item = proto_tree_add_item(type_tree, ofp_packet_out_data_hdr, tvb, offset, -1, FALSE);
                    proto_tree *data_tree = proto_item_add_subtree(data_item, ett_ofp_packet_out_data_hdr);
                    tvbuff_t *next_tvb = tvb_new_subset(tvb, offset, -1, total_len);
                    dissect_ethernet(next_tvb, pinfo, data_tree);
                }
                else {
                    /* if we couldn't load the ethernet dissector, just display the bytes */
                    add_child(type_tree, ofp_packet_out_data_hdr, tvb, &offset, total_len);
                }
            }

            break;
        }

        case OFPT_FLOW_MOD: {
            type_item = proto_tree_add_item(ofp_tree, ofp_flow_mod, tvb, offset, -1, FALSE);
            type_tree = proto_item_add_subtree(type_item, ett_ofp_flow_mod);

            dissect_match(type_tree, type_item, tvb, pinfo, &offset);
            add_child(type_tree, ofp_flow_mod_cookie, tvb, &offset, 8);
            add_child(type_tree, ofp_flow_mod_command, tvb, &offset, 2);
            add_child(type_tree, ofp_flow_mod_idle_timeout, tvb, &offset, 2);
            add_child(type_tree, ofp_flow_mod_hard_timeout, tvb, &offset, 2);
            add_child(type_tree, ofp_flow_mod_priority, tvb, &offset, 2);

            /* get buffer_id value for later use */
            guint32 buffer_id = tvb_get_ntohl( tvb, offset );

            if( buffer_id == 0xFFFFFFFF )
                add_child_str(type_tree, ofp_flow_mod_buffer_id, tvb, &offset, 4, "None");
            else {
                snprintf(str, STR_LEN, "%u", buffer_id);
                add_child_str(type_tree, ofp_flow_mod_buffer_id, tvb, &offset, 4, str);
            }

            /* add the output port */
            dissect_port(type_tree, ofp_flow_mod_out_port, tvb, &offset );
            dissect_flow_mod_flags(tvb, pinfo, type_tree, &offset);
            dissect_action_array(tvb, pinfo, type_tree, len, offset);
            break;
        }

        case OFPT_PORT_MOD: {
            type_item = proto_tree_add_item(ofp_tree, ofp_port_mod, tvb, offset, -1, FALSE);
            type_tree = proto_item_add_subtree(type_item, ett_ofp_port_mod);

            dissect_port_mod(type_tree, type_item, tvb, pinfo, &offset);
            break;
        }

        case OFPT_STATS_REQUEST: {
            type_item = proto_tree_add_item(ofp_tree, ofp_stats_request, tvb, offset, -1, FALSE);
            type_tree = proto_item_add_subtree(type_item, ett_ofp_stats_request);

            guint16 type = tvb_get_ntohs( tvb, offset );
            add_child(type_tree, ofp_stats_request_type, tvb, &offset, 2);
            add_child(type_tree, ofp_stats_request_flags, tvb, &offset, 2);

            switch( type ) {
            case OFPST_FLOW: {
                proto_item *flow_item = proto_tree_add_item(type_tree, ofp_flow_stats_request, tvb, offset, -1, FALSE);
                proto_tree *flow_tree = proto_item_add_subtree(flow_item, ett_ofp_flow_stats_request);

                dissect_match(flow_tree, flow_item, tvb, pinfo, &offset);

                guint8 id = tvb_get_guint8( tvb, offset );
                if( id == 0xFF )
                    add_child_str(flow_tree, ofp_flow_stats_request_table_id, tvb, &offset, 1, "All Tables");
                else {
                    snprintf(str, STR_LEN, "%u", id);
                    add_child_str(flow_tree, ofp_flow_stats_request_table_id, tvb, &offset, 1, str);
                }

                dissect_pad(flow_tree, &offset, 1);
                dissect_port(flow_tree, ofp_flow_stats_request_out_port, tvb, &offset );
                break;
            }

            case OFPST_AGGREGATE: {
                proto_item *aggr_item = proto_tree_add_item(type_tree, ofp_aggr_stats_request, tvb, offset, -1, FALSE);
                proto_tree *aggr_tree = proto_item_add_subtree(aggr_item, ett_ofp_aggr_stats_request);

                dissect_match(aggr_tree, aggr_item, tvb, pinfo, &offset);

                guint8 id = tvb_get_guint8( tvb, offset );
                if( id == 0xFF )
                    add_child_str(aggr_tree, ofp_aggr_stats_request_table_id, tvb, &offset, 1, "All Tables");
                else {
                    snprintf(str, STR_LEN, "%u", id);
                    add_child_str(aggr_tree, ofp_aggr_stats_request_table_id, tvb, &offset, 1, str);
                }

                dissect_pad(aggr_tree, &offset, 3);
                break;
            }

            case OFPST_TABLE:
                /* no body for these types of requests */
                break;

            case OFPST_PORT:{
		    if (len - offset > 0) {
			    proto_item *port_item = proto_tree_add_item(type_tree, ofp_port_stats_request, tvb, offset, -1, FALSE);
			    proto_tree *port_tree = proto_item_add_subtree(port_item, ett_ofp_port_stats_request);
			    dissect_port(port_tree, ofp_port_stats_request_port_no, tvb, &offset);
			    dissect_pad(port_tree, &offset, 6);
		    }
	    }
		    break;

            case OFPST_QUEUE: {
                proto_item *queue_item = proto_tree_add_item(type_tree, ofp_queue_stats_request, tvb, offset, -1, FALSE);
                proto_tree *queue_tree = proto_item_add_subtree(queue_item, ett_ofp_queue_stats_request);

                dissect_port(queue_tree, ofp_queue_stats_port_no, tvb, &offset);
                dissect_pad(queue_tree, &offset, 2);
                dissect_queue_id(queue_tree, ofp_queue_stats_queue_id, tvb, &offset);
                break;
            }

            default:
                /* add as bytes if type isn't one we know how to dissect */
                add_child(type_tree, ofp_stats_request_body, tvb, &offset, len - offset);
            }

            break;
        }

        case OFPT_STATS_REPLY: {
            type_item = proto_tree_add_item(ofp_tree, ofp_stats_reply, tvb, offset, -1, FALSE);
            type_tree = proto_item_add_subtree(type_item, ett_ofp_stats_reply);

            guint16 type = tvb_get_ntohs( tvb, offset );
            add_child(type_tree, ofp_stats_reply_type, tvb, &offset, 2);
            add_child(type_tree, ofp_stats_reply_flags, tvb, &offset, 2);

            switch( type ) {

            case OFPST_DESC: {
            	// FIXME: add desc stats
            	proto_item* desc_item = proto_tree_add_item(type_tree, ofp_desc_stats, tvb, offset, -1, FALSE);
            	proto_tree* desc_tree = proto_item_add_subtree(desc_item, ett_ofp_desc_stats);

                add_child( desc_tree, ofp_desc_stats_mfr_desc, tvb, &offset, DESC_STR_LEN );
                add_child( desc_tree, ofp_desc_stats_hw_desc, tvb, &offset, DESC_STR_LEN );
                add_child( desc_tree, ofp_desc_stats_sw_desc, tvb, &offset, DESC_STR_LEN );
                add_child( desc_tree, ofp_desc_stats_serial_num, tvb, &offset, SERIAL_NUM_LEN );
                add_child( desc_tree, ofp_desc_stats_dp_desc, tvb, &offset, DESC_STR_LEN );

            	break;
            }

            case OFPST_FLOW: {
                /* process each flow stats struct in the packet */
                while( offset < len ) {
                    proto_item* flow_item = proto_tree_add_item(type_tree, ofp_flow_stats_reply, tvb, offset, -1, FALSE);
                    proto_tree* flow_tree = proto_item_add_subtree(flow_item, ett_ofp_flow_stats_reply);

                    /* just get the length of this part of the packet; no need
                       to put it in the tree */
                    guint16 total_len = tvb_get_ntohs( tvb, offset );
                    guint offset_start = offset;
                    offset += 2;

                    add_child(flow_tree, ofp_flow_stats_reply_table_id, tvb, &offset, 1);
                    dissect_pad(flow_tree, &offset, 1);
                    dissect_match(flow_tree, flow_item, tvb, pinfo, &offset);
                    add_child(flow_tree, ofp_flow_stats_reply_duration_sec, tvb, &offset, 4);
                    add_child(flow_tree, ofp_flow_stats_reply_duration_nsec, tvb, &offset, 4);
                    add_child(flow_tree, ofp_flow_stats_reply_priority, tvb, &offset, 2);
                    add_child(flow_tree, ofp_flow_stats_reply_idle_timeout, tvb, &offset, 2);
                    add_child(flow_tree, ofp_flow_stats_reply_hard_timeout, tvb, &offset, 2);
                    dissect_pad(flow_tree, &offset, 6);
                    add_child(flow_tree, ofp_flow_stats_reply_cookie, tvb, &offset, 8);
                    add_child(flow_tree, ofp_flow_stats_reply_packet_count, tvb, &offset, 8);
                    add_child(flow_tree, ofp_flow_stats_reply_byte_count, tvb, &offset, 8);

                    /* parse the actions for this flow */
                    dissect_action_array(tvb, pinfo, flow_tree, total_len + offset_start, offset);
                    offset = total_len + offset_start;
                }
                break;
            }

            case OFPST_AGGREGATE: {
                proto_item* aggr_item = proto_tree_add_item(type_tree, ofp_aggr_stats_reply, tvb, offset, -1, FALSE);
                proto_tree* aggr_tree = proto_item_add_subtree(aggr_item, ett_ofp_aggr_stats_reply);

                add_child(aggr_tree, ofp_aggr_stats_reply_packet_count, tvb, &offset, 8);
                add_child(aggr_tree, ofp_aggr_stats_reply_byte_count, tvb, &offset, 8);
                add_child(aggr_tree, ofp_aggr_stats_reply_flow_count, tvb, &offset, 4);

                dissect_pad(aggr_tree, &offset, 4);
                break;
            }

            case OFPST_TABLE: {
                /* process each table stats struct in the packet */
                while( offset < len ) {
                    proto_item *table_item = proto_tree_add_item(type_tree, ofp_table_stats, tvb, offset, -1, FALSE);
                    proto_tree *table_tree = proto_item_add_subtree(table_item, ett_ofp_table_stats);

                    add_child(table_tree, ofp_table_stats_table_id, tvb, &offset, 1);
                    dissect_pad(table_tree, &offset, 3);
                    add_child( table_tree, ofp_table_stats_name, tvb, &offset, OFP_MAX_TABLE_NAME_LEN);
                    dissect_wildcards(table_tree, table_item, tvb, pinfo, &offset, ofp_table_stats_wildcards);
                    add_child(table_tree, ofp_table_stats_max_entries, tvb, &offset, 4);
                    add_child(table_tree, ofp_table_stats_active_count, tvb, &offset, 4);
                    add_child(table_tree, ofp_table_stats_lookup_count, tvb, &offset, 8);
                    add_child(table_tree, ofp_table_stats_matched_count, tvb, &offset, 8);
                }
                break;
            }

            case OFPST_PORT: {
                /* process each port stats struct in the packet */
                while( offset < len ) {
                    proto_item *port_item = proto_tree_add_item(type_tree, ofp_port_stats, tvb, offset, -1, FALSE);
                    proto_tree *port_tree = proto_item_add_subtree(port_item, ett_ofp_port_stats);

                    dissect_port(port_tree, ofp_port_stats_port_no, tvb, &offset);
                    dissect_pad(port_tree, &offset, 6);
                    add_child(port_tree, ofp_port_stats_rx_packets, tvb, &offset, 8);
                    add_child(port_tree, ofp_port_stats_tx_packets, tvb, &offset, 8);
                    add_child(port_tree, ofp_port_stats_rx_bytes, tvb, &offset, 8);
                    add_child(port_tree, ofp_port_stats_tx_bytes, tvb, &offset, 8);
                    add_child(port_tree, ofp_port_stats_rx_dropped, tvb, &offset, 8);
                    add_child(port_tree, ofp_port_stats_tx_dropped, tvb, &offset, 8);
                    add_child(port_tree, ofp_port_stats_rx_errors, tvb, &offset, 8);
                    add_child(port_tree, ofp_port_stats_tx_errors, tvb, &offset, 8);
                    add_child(port_tree, ofp_port_stats_rx_frame_err, tvb, &offset, 8);
                    add_child(port_tree, ofp_port_stats_rx_over_err, tvb, &offset, 8);
                    add_child(port_tree, ofp_port_stats_rx_crc_err, tvb, &offset, 8);
                    add_child(port_tree, ofp_port_stats_collisions, tvb, &offset, 8);
                }
                break;
            }

            case OFPST_QUEUE: {
                /* process each port stats struct in the packet */
                while( offset < len ) {
                    proto_item *queue_item = proto_tree_add_item(type_tree, ofp_queue_stats, tvb, offset, -1, FALSE);
                    proto_tree *queue_tree = proto_item_add_subtree(queue_item, ett_ofp_queue_stats);

                    dissect_port(queue_tree, ofp_queue_stats_port_no, tvb, &offset);
                    dissect_pad(queue_tree, &offset, 2);
					dissect_queue_id(queue_tree, ofp_queue_stats_queue_id, tvb, &offset);
                    add_child(queue_tree, ofp_queue_stats_tx_bytes, tvb, &offset, 8);
                    add_child(queue_tree, ofp_queue_stats_tx_packets, tvb, &offset, 8);
                    add_child(queue_tree, ofp_queue_stats_tx_errors, tvb, &offset, 8);
                }
                break;
            }

            case OFPST_VENDOR: {
                proto_item* vendor_item = proto_tree_add_item(type_tree, ofp_vendor_stats, tvb, offset, -1, FALSE);
                proto_tree* vendor_tree = proto_item_add_subtree(vendor_item, ett_ofp_vendor_stats);

                add_child(vendor_tree, ofp_vendor_stats_vendor, tvb, &offset, 4);
                add_child(vendor_tree, ofp_vendor_stats_body, tvb, &offset, len - offset);
               	
            	break;
            }

            default:
                /* add as bytes if type isn't one we know how to dissect */
                add_child(type_tree, ofp_stats_reply_body, tvb, &offset, len - offset);
            }

            break;
        }

        default:
            /* add a warning if we encounter an unrecognized packet type */
            snprintf(str, STR_LEN, "Dissector does not recognize type %u", type);
            add_child_str(tree, ofp_header_warn_type, tvb, &offset, len - offset, str);
        }
    }
}

static void dissect_openflow(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    /* have wireshark reassemble our PDUs; call dissect_openflow_when full PDU assembled */
    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 4, get_openflow_message_len, dissect_openflow_message);
}
