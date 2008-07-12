/**
 * Filename: packet-openflow.c
 * Author:   David Underhill
 * Updated:  2008-Jul-12
 * Purpose:  define a Wireshark 1.0.0+ dissector for the OpenFlow protocol
 *           version 0x83
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
#include <string.h>
#include <arpa/inet.h>
#include <openflow.h>

/** if 0, padding bytes will not be shown in the dissector */
#define SHOW_PADDING 0

/** the version of openflow this dissector was written for */
#define DISSECTOR_OPENFLOW_VERSION 0x83

#define PROTO_TAG_OPENFLOW	"OPENFLOW"

/* Wireshark ID of the OPENFLOW protocol */
static int proto_openflow = -1;
static dissector_handle_t openflow_handle;
static void dissect_openflow(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* traffic will arrive with TCP port OPENFLOW_DST_TCP_PORT */
#define TCP_PORT_FILTER "tcp.port"
static int global_openflow_proto = OPENFLOW_DST_TCP_PORT;

/* try to find the ethernet dissector to dissect encapsulated Ethernet data */
static dissector_handle_t data_ethernet;

/* AM=Async message, CSM=Control/Switch Message */
/** names to bind to various values in the type field */
static const value_string names_ofp_type[] = {
    { OFPT_FEATURES_REQUEST,    "CSM: Features Request" },
    { OFPT_FEATURES_REPLY,      "CSM: Features Reply" },
    { OFPT_GET_CONFIG_REQUEST,  "CSM: Get Config Request" },
    { OFPT_GET_CONFIG_REPLY,    "CSM: Get Config Reply" },
    { OFPT_SET_CONFIG,          "CSM: Set Config" },
    { OFPT_PACKET_IN,           "AM:  Packet In" },
    { OFPT_PACKET_OUT,          "CSM: Packet Out" },
    { OFPT_FLOW_MOD,            "CSM: Flow Mod" },
    { OFPT_FLOW_EXPIRED,        "AM:  Flow Expired" },
    { OFPT_TABLE,               "CSM: Table" },
    { OFPT_PORT_MOD,            "CSM: Port Mod" },
    { OFPT_PORT_STATUS,         "AM:  Port Status" },
    { OFPT_STATS_REQUEST,       "CSM: Stats Request" },
    { OFPT_STATS_REPLY,         "CSM: Stats Reply" },
    { OFPT_ERROR_MSG,           "AM:  Error Message" },
    { 0,                        NULL }
};
#define OFP_TYPE_MAX_VALUE OFPT_ERROR_MSG

/** names of flags in ofp_port_flags */
static const value_string names_ofp_port_flags[] = {
    { OFPPFL_NO_FLOOD, "Do not include this port when flooding" },
    { 0,               NULL }
};
#define NUM_PORT_FLAGS 1

/** names from ofp_port */
static const value_string names_ofp_port[] = {
    { OFPP_TABLE,      "Perform actions in flow table" },
    { OFPP_NORMAL,     "Process with normal L2/L3 switching" },
    { OFPP_FLOOD,      "All physical ports except input port and those disabled by STP" },
    { OFPP_ALL,        "All physical ports except input port" },
    { OFPP_CONTROLLER, "Send to controller" },
    { OFPP_LOCAL,      "Local openflow 'port'" },
    { OFPP_NONE,       "Not associated with a physical port" },
    { 0,               NULL }
};

/** names from ofp_port_features */
static const value_string names_ofp_port_features[] = {
    { OFPPF_10MB_HD,   " 10 Mb half-duplex rate support" },
    { OFPPF_10MB_FD,   " 10 Mb full-duplex rate support" },
    { OFPPF_100MB_HD,  "100 Mb half-duplex rate support" },
    { OFPPF_100MB_FD,  "100 Mb full-duplex rate support" },
    { OFPPF_1GB_HD,    "  1 Gb half-duplex rate support" },
    { OFPPF_1GB_FD,    "  1 Gb full-duplex rate support" },
    { OFPPF_10GB_FD,   " 10 Gb full-duplex rate support" },
    { 0, NULL }
};
#define NUM_PORT_FEATURES 7

/** names from ofp_flow_wildcards */
static const value_string names_ofp_flow_wildcards[] = {
    { OFPFW_IN_PORT,  "Switch input port" },
    { OFPFW_DL_VLAN,  "VLAN" },
    { OFPFW_DL_SRC,   "Ethernet source address" },
    { OFPFW_DL_DST,   "Ethernet destination address" },
    { OFPFW_DL_TYPE,  "Ethernet frame type" },
    { OFPFW_NW_SRC,   "IP source address" },
    { OFPFW_NW_DST,   "IP destination address" },
    { OFPFW_NW_PROTO, "IP protocol" },
    { OFPFW_TP_SRC,   "TCP/UDP source port" },
    { OFPFW_TP_DST,   "TCP/UDP destination port" },
    { 0, NULL }
};
#define NUM_WILDCARDS 10

/** names from ofp_action_type */
static const value_string names_ofp_action_type[] = {
    { OFPAT_OUTPUT,      "Output to switch port" },
    { OFPAT_SET_DL_VLAN, "VLAN" },
    { OFPAT_SET_DL_SRC,  "Ethernet source address" },
    { OFPAT_SET_DL_DST,  "Ethernet destination address" },
    { OFPAT_SET_NW_SRC,  "IP source address" },
    { OFPAT_SET_NW_DST,  "IP destination address" },
    { OFPAT_SET_TP_SRC,  "TCP/UDP source port" },
    { OFPAT_SET_TP_DST,  "TCP/UDP destination port"},
    { 0,                 NULL }
};
#define NUM_ACTIONS 8

/** names from ofp_capabilities */
static const value_string names_ofp_capabilities[] = {
    { OFPC_FLOW_STATS,   "Flow statistics" },
    { OFPC_TABLE_STATS,  "Table statistics" },
    { OFPC_PORT_STATS,   "Port statistics" },
    { OFPC_STP,          "802.11d spanning tree" },
    { OFPC_MULTI_PHY_TX, "Supports transmitting through multiple physical interface" },
    { 0,                 NULL }
};
#define NUM_CAPABILITIES 5

/** yes/no for bitfields field */
static const value_string names_choice[] = {
    { 0, "No"  },
    { 1, "Yes" },
    { 0, NULL  }
};

/** names from ofp_flow_mod_command */
static const value_string names_flow_mod_command[] = {
    { OFPFC_ADD,           "New flow" },
    { OFPFC_DELETE,        "Delete all matching flows" },
    { OFPFC_DELETE_STRICT, "Strictly match wildcards and priority" },
    { 0,                   NULL }
};

/** names of stats_types */
static const value_string names_stats_types[] = {
    { OFPST_FLOW,      "Individual flow statistics. The request body is struct ofp_flow_stats_request. The reply body is an array of struct ofp_flow_stats." },
    { OFPST_AGGREGATE, "Aggregate flow statistics. The request body is struct ofp_aggregate_stats_request. The reply body is struct ofp_aggregate_stats_reply." },
    { OFPST_TABLE,     "Flow table statistics. The request body is empty. The reply body is an array of struct ofp_table_stats." },
    { OFPST_PORT,      "Physical port statistics. The request body is empty. The reply body is an array of struct ofp_port_stats." },
    { 0, NULL }
};

/** names of ofp_reason */
static const value_string names_ofp_reason[] = {
    { OFPR_NO_MATCH, "No matching flow" },
    { OFPR_ACTION,   "Action explicitly output to controller" },
    { 0,             NULL }
};

/** names from ofp_flow_mod_command */
static const value_string names_ofp_port_reason[] = {
    { OFPPR_ADD,    "The port was added" },
    { OFPPR_DELETE, "The port was removed" },
    { OFPPR_MOD,    "Some attribute of the port has changed" },
    { 0,            NULL }
};

/* These variables are used to hold the IDs of our fields; they are
 * set when we call proto_register_field_array() in proto_register_openflow()
 */
static gint ofp                = -1;

/* Open Flow Header */
static gint ofp_header         = -1;
static gint ofp_header_version = -1;
static gint ofp_header_type    = -1;
static gint ofp_header_length  = -1;
static gint ofp_header_xid     = -1;
static gint ofp_header_warn_ver = -1;
static gint ofp_header_warn_type = -1;

/* Common Structures */
static gint ofp_phy_port          = -1;
static gint ofp_phy_port_port_no  = -1;
static gint ofp_phy_port_hw_addr  = -1;
static gint ofp_phy_port_name     = -1;
static gint ofp_phy_port_flags_hdr= -1;
static gint ofp_phy_port_flags[NUM_PORT_FLAGS];
static gint ofp_phy_port_speed    = -1;
static gint ofp_phy_port_features_hdr = -1;
static gint ofp_phy_port_features[NUM_PORT_FEATURES];

static gint ofp_match           = -1;
static gint ofp_match_wildcards = -1;
static gint ofp_match_wildcard[NUM_WILDCARDS];
static gint ofp_match_in_port   = -1;
static gint ofp_match_dl_src    = -1;
static gint ofp_match_dl_dst    = -1;
static gint ofp_match_dl_vlan   = -1;
static gint ofp_match_dl_type   = -1;
static gint ofp_match_nw_src    = -1;
static gint ofp_match_nw_dst    = -1;
static gint ofp_match_nw_proto  = -1;
static gint ofp_match_pad       = -1;
static gint ofp_match_tp_src    = -1;
static gint ofp_match_tp_dst    = -1;
static gint ofp_match_unknown   = -1;

static gint ofp_action         = -1;
static gint ofp_action_type    = -1;
static gint ofp_action_vlan_id = -1;
static gint ofp_action_dl_addr = -1;
static gint ofp_action_nw_addr = -1;
static gint ofp_action_tp      = -1;
static gint ofp_action_unknown = -1;
static gint ofp_action_warn    = -1;
static gint ofp_action_num     = -1;

/* type: ofp_action_output */
static gint ofp_action_output         = -1;
static gint ofp_action_output_max_len = -1;
static gint ofp_action_output_port    = -1;

/* Controller/Switch Messages */
static gint ofp_switch_features               = -1;
static gint ofp_switch_features_datapath_id   = -1;
static gint ofp_switch_features_table_info_hdr= -1;
static gint ofp_switch_features_n_exact       = -1;
static gint ofp_switch_features_n_compression = -1;
static gint ofp_switch_features_n_general     = -1;
static gint ofp_switch_features_buffer_limits_hdr = -1;
static gint ofp_switch_features_buffer_mb     = -1;
static gint ofp_switch_features_n_buffers     = -1;
static gint ofp_switch_features_capabilities_hdr = -1;
static gint ofp_switch_features_capabilities[NUM_CAPABILITIES];
static gint ofp_switch_features_actions_hdr = -1;
static gint ofp_switch_features_actions_warn = -1;
static gint ofp_switch_features_actions[NUM_ACTIONS];
static gint ofp_switch_features_ports_hdr = -1;
static gint ofp_switch_features_ports_num = -1;
static gint ofp_switch_features_ports_warn = -1;

static gint ofp_switch_config               = -1;
/* flags handled by ofp_switch_features_capabilities */
static gint ofp_switch_config_miss_send_len = -1;

static gint ofp_flow_mod           = -1;
static gint ofp_flow_mod_command   = -1;
static gint ofp_flow_mod_max_idle  = -1;
static gint ofp_flow_mod_buffer_id = -1;
static gint ofp_flow_mod_priority  = -1;
static gint ofp_flow_mod_pad       = -1;
static gint ofp_flow_mod_reserved  = -1;

static gint ofp_port_mod      = -1;
/* field: ofp_phy_port */

static gint ofp_stats_request       = -1;
static gint ofp_stats_request_type  = -1;
static gint ofp_stats_request_flags = -1;
static gint ofp_stats_request_body  = -1;

static gint ofp_stats_reply       = -1;
static gint ofp_stats_reply_type  = -1;
static gint ofp_stats_reply_flags = -1;
static gint ofp_stats_reply_body  = -1;

static gint ofp_flow_stats_request          = -1;
/* field: ofp_match */
static gint ofp_flow_stats_request_table_id = -1;
static gint ofp_flow_stats_request_pad      = -1;

static gint ofp_flow_stats              = -1;
static gint ofp_flow_stats_length       = -1;
static gint ofp_flow_stats_table_id     = -1;
static gint ofp_flow_stats_pad          = -1;
static gint ofp_flow_stats_match        = -1;
static gint ofp_flow_stats_duration     = -1;
static gint ofp_flow_stats_packet_count = -1;
static gint ofp_flow_stats_byte_count   = -1;
static gint ofp_flow_stats_priority     = -1;
static gint ofp_flow_stats_max_idle     = -1;
static gint ofp_flow_stats_actions      = -1;

static gint ofp_aggregate_stats_request          = -1;
/* field: ofp_match */
static gint ofp_aggregate_stats_request_table_id = -1;
static gint ofp_aggregate_stats_request_pad      = -1;

static gint ofp_aggregate_stats_reply              = -1;
static gint ofp_aggregate_stats_reply_packet_count = -1;
static gint ofp_aggregate_stats_reply_byte_count   = -1;
static gint ofp_aggregate_stats_reply_flow_count   = -1;

static gint ofp_table_stats               = -1;
static gint ofp_table_stats_table_id      = -1;
static gint ofp_table_stats_pad           = -1;
static gint ofp_table_stats_name          = -1;
static gint ofp_table_stats_max_entries   = -1;
static gint ofp_table_stats_active_count  = -1;
static gint ofp_table_stats_matched_count = -1;

static gint ofp_port_stats            = -1;
static gint ofp_port_stats_port_no    = -1;
static gint ofp_port_stats_pad        = -1;
static gint ofp_port_stats_rx_count   = -1;
static gint ofp_port_stats_tx_count   = -1;
static gint ofp_port_stats_drop_count = -1;

static gint ofp_packet_out           = -1;
static gint ofp_packet_out_buffer_id = -1;
static gint ofp_packet_out_in_port   = -1;
static gint ofp_packet_out_out_port  = -1;
static gint ofp_packet_out_actions_hdr = -1;
static gint ofp_packet_out_data_hdr  = -1;

/* Asynchronous Messages */
static gint ofp_packet_in        = -1;
static gint ofp_packet_in_buffer_id = -1;
static gint ofp_packet_in_total_len = -1;
static gint ofp_packet_in_in_port   = -1;
static gint ofp_packet_in_reason    = -1;
static gint ofp_packet_in_pad       = -1;
static gint ofp_packet_in_data_hdr  = -1;

static gint ofp_flow_expired              = -1;
/* field: ofp_match */
static gint ofp_flow_expired_priority     = -1;
static gint ofp_flow_expired_pad          = -1;
static gint ofp_flow_expired_duration     = -1;
static gint ofp_flow_expired_packet_count = -1;
static gint ofp_flow_expired_byte_count   = -1;

static gint ofp_port_status        = -1;
static gint ofp_port_status_reason = -1;
static gint ofp_port_status_pad    = -1;
static gint ofp_port_status_desc   = -1;

static gint ofp_error_msg      = -1;
static gint ofp_error_msg_type = -1;
static gint ofp_error_msg_code = -1;
static gint ofp_error_msg_data = -1;

/* These are the ids of the subtrees that we may be creating */
static gint ett_ofp = -1;

/* Open Flow Header */
static gint ett_ofp_header = -1;

/* Common Structures */
static gint ett_ofp_phy_port = -1;
static gint ett_ofp_phy_port_flags_hdr = -1;
static gint ett_ofp_phy_port_features_hdr = -1;
static gint ett_ofp_match = -1;
static gint ett_ofp_match_wildcards = -1;
static gint ett_ofp_action = -1;
static gint ett_ofp_action_output = -1;

/* Controller/Switch Messages */
static gint ett_ofp_switch_features = -1;
static gint ett_ofp_switch_features_table_info_hdr = -1;
static gint ett_ofp_switch_features_buffer_limits_hdr = -1;
static gint ett_ofp_switch_features_capabilities_hdr = -1;
static gint ett_ofp_switch_features_actions_hdr = -1;
static gint ett_ofp_switch_features_actions_warn = -1;
static gint ett_ofp_switch_features_ports_hdr = -1;
static gint ett_ofp_switch_features_ports_warn = -1;
static gint ett_ofp_switch_config = -1;
static gint ett_ofp_flow_mod = -1;
static gint ett_ofp_port_mod = -1;
static gint ett_ofp_stats_request = -1;
static gint ett_ofp_stats_reply = -1;
static gint ett_ofp_flow_stats_request = -1;
static gint ett_ofp_flow_stats = -1;
static gint ett_ofp_aggregate_stats_request = -1;
static gint ett_ofp_aggregate_stats_reply = -1;
static gint ett_ofp_table_stats = -1;
static gint ett_ofp_port_stats = -1;
static gint ett_ofp_packet_out = -1;
static gint ett_ofp_packet_out_actions_hdr = -1;
static gint ett_ofp_packet_out_data_hdr  = -1;

/* Asynchronous Messages */
static gint ett_ofp_packet_in = -1;
static gint ett_ofp_packet_in_data_hdr = -1;
static gint ett_ofp_flow_expired = -1;
static gint ett_ofp_port_status = -1;
static gint ett_ofp_error_msg = -1;

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
    for( i=0; i<NUM_CAPABILITIES; i++ ) {
        ofp_switch_features_capabilities[i] = -1;
    }
    for( i=0; i<NUM_ACTIONS; i++ ) {
        ofp_switch_features_actions[i] = -1;
    }
    for( i=0; i<NUM_PORT_FLAGS; i++ ) {
        ofp_phy_port_flags[i] = -1;
    }
    for( i=0; i<NUM_PORT_FEATURES; i++ ) {
        ofp_phy_port_features[i] = -1;
    }
    for( i=0; i<NUM_WILDCARDS; i++ ) {
        ofp_match_wildcard[i] = -1;
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
        /* CS: Physical Port Information */
        { &ofp_phy_port,
          { "Physical Port", "of.port", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Physical Port", HFILL }},

        { &ofp_phy_port_port_no,
          { "Port #", "of.port_no", FT_UINT16, BASE_DEC, NO_STRINGS, NO_MASK, "Port #", HFILL }},

        { &ofp_phy_port_hw_addr,
          { "MAC Address", "of.port_hw_addr", FT_ETHER, BASE_NONE, NO_STRINGS, NO_MASK, "MAC Address", HFILL }},

        { &ofp_phy_port_name,
          { "Port Name", "of.port_port_name", FT_STRING, BASE_NONE, NO_STRINGS, NO_MASK, "Port Name", HFILL }},

        { &ofp_phy_port_flags_hdr,
          { "Flags", "of.port_flags", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Flags", HFILL }},

        { &ofp_phy_port_flags[0],
          { "  Do not include this port when flooding", "of.port_flags_flood", FT_UINT32, BASE_DEC, VALS(names_choice), OFPPFL_NO_FLOOD, "Do not include this port when flooding", HFILL }},

        { &ofp_phy_port_speed,
          { "Speed (Mbps)", "of.port_speed", FT_UINT32, BASE_DEC, NO_STRINGS, NO_MASK, "Speed (Mbps)", HFILL }},

        { &ofp_phy_port_features_hdr,
          { "Features", "of.port_features", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Features", HFILL }},

        { &ofp_phy_port_features[0],
          { "   10 Mb half-duplex rate support", "of.port_features_10mb_hd" , FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_10MB_HD, "10 Mb half-duplex rate support", HFILL }},

        { &ofp_phy_port_features[1],
          { "   10 Mb full-duplex rate support", "of.port_features_10mb_fd",  FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_10MB_FD, "10 Mb full-duplex rate support", HFILL }},

        { &ofp_phy_port_features[2],
          { "  100 Mb half-duplex rate support", "of.port_features_100mb_hd", FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_100MB_HD, "100 Mb half-duplex rate support", HFILL }},

        { &ofp_phy_port_features[3],
          { "  100 Mb full-duplex rate support", "of.port_features_100mb_fd", FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_100MB_FD, "100 Mb full-duplex rate support", HFILL }},

        { &ofp_phy_port_features[4],
          { "    1 Gb half-duplex rate support", "of.port_features_1gb_hd",   FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_1GB_HD, "1 Gb half-duplex rate support", HFILL }},

        { &ofp_phy_port_features[5],
          { "    1 Gb full-duplex rate support", "of.port_features_1gb_fd",   FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_1GB_FD, "1 Gb full-duplex rate support", HFILL }},

        { &ofp_phy_port_features[6],
          { "   10 Gb full-duplex rate support", "of.port_features_10gb_hd",  FT_UINT32, BASE_DEC, VALS(names_choice), OFPPF_10GB_FD, "10 Gb full-duplex rate support", HFILL }},


        /* CS: match */
        { &ofp_match,
          { "Match", "of.match", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Match", HFILL }},

        { &ofp_match_wildcards,
          { "Match Types", "of.wildcards", FT_UINT16, BASE_HEX, NO_STRINGS, NO_MASK, "Match Types (Wildcards)", HFILL }},

        { &ofp_match_wildcard[0],
          { "  Input port", "of.wildcard_in_port" , FT_UINT16, BASE_DEC, VALS(names_choice), OFPFW_IN_PORT, "Input Port", HFILL }},

        { &ofp_match_wildcard[1],
          { "  VLAN", "of.wildcard_dl_vlan" , FT_UINT16, BASE_DEC, VALS(names_choice), OFPFW_DL_VLAN, "VLAN", HFILL }},

        { &ofp_match_wildcard[2],
          { "  Ethernet Src Addr", "of.wildcard_dl_src" , FT_UINT16, BASE_DEC, VALS(names_choice), OFPFW_DL_SRC, "Ethernet Source Address", HFILL }},

        { &ofp_match_wildcard[3],
          { "  Ethernet Dst Addr", "of.wildcard_dl_dst" , FT_UINT16, BASE_DEC, VALS(names_choice), OFPFW_DL_DST, "Ethernet Destination Address", HFILL }},

        { &ofp_match_wildcard[4],
          { "  Ethernet Type", "of.wildcard_dl_type" , FT_UINT16, BASE_DEC, VALS(names_choice), OFPFW_DL_TYPE, "Ethernet Type", HFILL }},

        { &ofp_match_wildcard[5],
          { "  IP Src Addr", "of.wildcard_nw_src" , FT_UINT16, BASE_DEC, VALS(names_choice), OFPFW_NW_SRC, "IP Source Address", HFILL }},

        { &ofp_match_wildcard[6],
          { "  IP Dst Addr", "of.wildcard_nw_dst" , FT_UINT16, BASE_DEC, VALS(names_choice), OFPFW_NW_DST, "IP Destination Address", HFILL }},

        { &ofp_match_wildcard[7],
          { "  IP Protocol", "of.wildcard_nw_proto" , FT_UINT16, BASE_DEC, VALS(names_choice), OFPFW_NW_PROTO, "IP Protocol", HFILL }},

        { &ofp_match_wildcard[8],
          { "  TCP/UDP Src Port", "of.wildcard_tp_src" , FT_UINT16, BASE_DEC, VALS(names_choice), OFPFW_TP_SRC, "TCP/UDP Source Port", HFILL }},

        { &ofp_match_wildcard[9],
          { "  TCP/UDP Dst Port", "of.wildcard_tp_dst" , FT_UINT16, BASE_DEC, VALS(names_choice), OFPFW_TP_DST, "TCP/UDP Destinatoin Port", HFILL }},

        { &ofp_match_in_port,
          { "Input Port", "of.match_in_port", FT_UINT16, BASE_DEC, NO_STRINGS, NO_MASK, "Input Port", HFILL }},

        { &ofp_match_dl_src,
          { "Ethernet Src Addr", "of.match_dl_src", FT_ETHER, BASE_NONE, NO_STRINGS, NO_MASK, "Source MAC Address", HFILL }},

        { &ofp_match_dl_dst,
          { "Ethernet Dst Addr", "of.match_dl_dst", FT_ETHER, BASE_NONE, NO_STRINGS, NO_MASK, "Destination MAC Address", HFILL }},

        { &ofp_match_dl_vlan,
          { "Input VLAN", "of.match_dl_vlan", FT_UINT16, BASE_DEC, NO_STRINGS, NO_MASK, "Input VLAN", HFILL }},

        { &ofp_match_dl_type,
          { "Ethernet Type", "of.match_dl_type", FT_UINT16, BASE_HEX, NO_STRINGS, NO_MASK, "Ethernet Type", HFILL }},

        { &ofp_match_nw_src,
          { "IP Src Addr", "of.match_nw_src", FT_IPv4, BASE_DEC, NO_STRINGS, NO_MASK, "Source IP Address", HFILL }},

        { &ofp_match_nw_dst,
          { "IP Dst Addr", "of.match_nw_dst", FT_IPv4, BASE_DEC, NO_STRINGS, NO_MASK, "Destination IP Address", HFILL }},

        { &ofp_match_nw_proto,
          { "IP Protocol", "of.match_", FT_UINT8, BASE_HEX, NO_STRINGS, NO_MASK, "IP Protocol", HFILL }},

        { &ofp_match_pad,
          { "Pad", "of.match_pad", FT_UINT8, BASE_DEC, NO_STRINGS, NO_MASK, "Pad", HFILL }},

        { &ofp_match_tp_src,
          { "TCP/UDP Src Port", "of.match_tp_src", FT_UINT16, BASE_DEC, NO_STRINGS, NO_MASK, "TCP/UDP Source Port", HFILL }},

        { &ofp_match_tp_dst,
          { "TCP/UDP Dst Port", "of.match_tp_dst", FT_UINT16, BASE_DEC, NO_STRINGS, NO_MASK, "TCP/UDP Destination Port", HFILL }},


        /* CS: active type */
        { &ofp_action,
          { "Action", "of.action", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Action", HFILL }},

        { &ofp_action_type,
          { "Type", "of.action_type", FT_UINT16, BASE_DEC, VALS(names_ofp_action_type), NO_MASK, "Action Type", HFILL }},

        { &ofp_action_vlan_id,
          { "VLAN ID", "of.action_vland_id", FT_UINT16, BASE_DEC, NO_STRINGS, NO_MASK, "VLAN ID", HFILL }},

        { &ofp_action_dl_addr,
          { "MAC Addr", "of.action_dl_addr", FT_ETHER, BASE_NONE, NO_STRINGS, NO_MASK, "MAC Addr", HFILL }},

        { &ofp_action_nw_addr,
          { "IP Addr", "of.action_nw_addr", FT_IPv4, BASE_NONE, NO_STRINGS, NO_MASK, "IP Addr", HFILL }},

        { &ofp_action_tp,
          { "Port", "of.action_port", FT_UINT16, BASE_DEC, NO_STRINGS, NO_MASK, "TCP/UDP Port", HFILL }},

        { &ofp_action_unknown,
          { "Unknown Action Type", "of.action_unknown", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Unknown Action Type", HFILL }},

        { &ofp_action_warn,
          { "Warning", "of.action_warn", FT_STRING, BASE_NONE, NO_STRINGS, NO_MASK, "Warning", HFILL }},

        { &ofp_action_num,
          { "# of Actions", "of.action_num", FT_UINT32, BASE_DEC, NO_STRINGS, NO_MASK, "Number of Actions", HFILL }},

        /* CS: ofp_action_output */
        { &ofp_action_output,
          { "Output Action", "of.action_output", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Output Action", HFILL }},

        { &ofp_action_output_max_len,
          { "Max Bytes to Send", "of.action_output_max_len", FT_STRING, BASE_NONE, NO_STRINGS, NO_MASK, "Maximum Bytes to Send", HFILL }},

        { &ofp_action_output_port,
          { "Port", "of.action_output_port", FT_UINT16, BASE_DEC, NO_STRINGS, NO_MASK, "Port", HFILL }},


        /* CSM: Features Request */
        /* nothing beyond the header */


        /* CSM: Features Reply */
        { &ofp_switch_features,
          { "Switch Features", "of.sf", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Switch Features", HFILL }},

        { &ofp_switch_features_datapath_id,
          { "Datapath ID", "of.sf_datapath_id", FT_UINT64, BASE_DEC, NO_STRINGS, NO_MASK, "Datapath ID", HFILL }},

        { &ofp_switch_features_table_info_hdr,
          { "Table Info", "of.sf_table_info", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Table Info", HFILL }},

        { &ofp_switch_features_n_exact,
          { "Max Exact-Match", "of.sf_n_exact", FT_UINT32, BASE_DEC, NO_STRINGS, NO_MASK, "Max Exact-Match", HFILL }},

        { &ofp_switch_features_n_compression,
          { "Max Entries Compressed", "of.sf_n_compression", FT_UINT32, BASE_DEC, NO_STRINGS, NO_MASK, "Max Entries Compressed", HFILL }},

        { &ofp_switch_features_n_general,
          { "Max Arbitrary Form Entries", "of.sf_n_general", FT_UINT32, BASE_DEC, NO_STRINGS, NO_MASK, "Max Arbitrary Form Entries", HFILL }},

        { &ofp_switch_features_buffer_limits_hdr,
          { "Buffer Limits", "of.sf_buffer_limits", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Buffer Limits", HFILL }},

        { &ofp_switch_features_buffer_mb,
          { "Buffer Space (MB)", "of.sf_buffer_mb", FT_UINT32, BASE_DEC, NO_STRINGS, NO_MASK, "", HFILL }},

        { &ofp_switch_features_n_buffers,
          { "Max Packets Buffered", "of.sf_", FT_UINT32, BASE_DEC, NO_STRINGS, NO_MASK, "", HFILL }},

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
          { "  Supports transmitting through multiple physical interface", "of.sf_capabilities_multi_phy_tx", FT_UINT32, BASE_DEC, VALS(names_choice), OFPC_MULTI_PHY_TX,  "Supports transmitting through multiple physical interface", HFILL }},

        { &ofp_switch_features_actions_hdr,
          { "Actions", "of.sf_actions", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Actions", HFILL }},

        { &ofp_switch_features_actions_warn,
          { "Warning: Actions are meaningless until version 0x90", "of.sf_actions_warn", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Warning", HFILL }},

        { &ofp_switch_features_actions[0],
          { "  Output to switch port", "of.sf_actions_output", FT_UINT32, BASE_DEC, VALS(names_choice), OFPAT_OUTPUT, "Output to switch port", HFILL }},

        { &ofp_switch_features_actions[1],
          { "  VLAN", "of.sf_actions_vlan", FT_UINT32, BASE_DEC, VALS(names_choice), OFPAT_SET_DL_VLAN, "VLAN", HFILL }},

        { &ofp_switch_features_actions[2],
          { "  Ethernet source address", "of.sf_actions_eth_src_addr", FT_UINT32, BASE_DEC, VALS(names_choice), OFPAT_SET_DL_SRC, "Ethernet source address", HFILL }},

        { &ofp_switch_features_actions[3],
          { "  Ethernet destination address", "of.sf_actions_eth_dst_addr", FT_UINT32, BASE_DEC, VALS(names_choice), OFPAT_SET_DL_DST, "Ethernet destination address", HFILL }},

        { &ofp_switch_features_actions[4],
          { "  IP source address", "of.sf_actions_ip_src_addr", FT_UINT32, BASE_DEC, VALS(names_choice), OFPAT_SET_NW_SRC, "IP source address", HFILL }},

        { &ofp_switch_features_actions[5],
          { "  IP destination address", "of.sf_actions_ip_dst_addr", FT_UINT32, BASE_DEC, VALS(names_choice), OFPAT_SET_NW_DST, "IP destination address", HFILL }},

        { &ofp_switch_features_actions[6],
          { "  TCP/UDP source", "of.sf_actions_src_port", FT_UINT32, BASE_DEC, VALS(names_choice), OFPAT_SET_TP_SRC, "TCP/UDP source port", HFILL }},

        { &ofp_switch_features_actions[7],
          { "  TCP/UDP destination", "of.sf_actions_dst_port", FT_UINT32, BASE_DEC, VALS(names_choice), OFPAT_SET_TP_DST, "TCP/UDP destination port", HFILL }},

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

        { &ofp_switch_config_miss_send_len,
          { "Max Bytes of New Flow to Send to Controller", "of.sc_", FT_UINT16, BASE_DEC, NO_STRINGS, NO_MASK, "Max Bytes of New Flow to Send to Controller", HFILL } },


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
          { "Reason Sent", "of.pktin_reason", FT_UINT8, BASE_DEC, VALS(names_ofp_reason), NO_MASK, "Reason Packet Sent", HFILL }},

        { &ofp_packet_in_pad,
          { "Padding", "of.pktin_pad", FT_UINT8, BASE_DEC, NO_STRINGS, NO_MASK, "Pad", HFILL }},

        { &ofp_packet_in_data_hdr,
          { "Frame Data", "of.pktin_data", FT_BYTES, BASE_NONE, NO_STRINGS, NO_MASK, "Frame Data", HFILL }},


        /* CSM: Packet Out */
       { &ofp_packet_out,
          { "Packet Out", "of.pktout", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Packet Out", HFILL }},

        { &ofp_packet_out_buffer_id,
          { "Buffer ID", "of.pktout_buffer_id", FT_STRING, BASE_NONE, NO_STRINGS, NO_MASK, "Buffer ID", HFILL }},

        { &ofp_packet_out_in_port,
          { "Frame Recv Port", "of.pktout_in_port", FT_STRING, BASE_NONE, NO_STRINGS, NO_MASK, "Port Frame was Received On", HFILL }},

        { &ofp_packet_out_out_port,
          { "Frame Output Port", "of.pktout_out_port", FT_UINT16, BASE_DEC, NO_STRINGS, NO_MASK, "Port Frame was Sent Out", HFILL }},

        { &ofp_packet_out_actions_hdr,
          { "Actions to Apply", "of.pktout_actions", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Actions to Apply to Packet", HFILL }},

        { &ofp_packet_out_data_hdr,
          { "Frame Data", "of.pktout_data", FT_BYTES, BASE_NONE, NO_STRINGS, NO_MASK, "Frame Data", HFILL }},


        /* CSM: Flow Mod */
        { &ofp_flow_mod,
          { "Flow Modification", "of.fm", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Flow Modification", HFILL } },

        { &ofp_flow_mod_command,
          { "Command", "of.fm_command", FT_UINT16, BASE_DEC, VALS(names_flow_mod_command), NO_MASK, "Command", HFILL } },

        { &ofp_flow_mod_max_idle,
          { "Idle Time (sec) Before Discarding", "of.fm_max_idle", FT_UINT16, BASE_DEC, NO_STRINGS, NO_MASK, "Idle Time (sec) Before Discarding", HFILL } },

        { &ofp_flow_mod_buffer_id,
          { "Buffer ID", "of.fm_buffer_id", FT_UINT32, BASE_DEC, NO_STRINGS, NO_MASK, "Buffer ID", HFILL } },

        { &ofp_flow_mod_priority,
          { "Priority", "of.fm_priority", FT_UINT16, BASE_DEC, NO_STRINGS, NO_MASK, "Priority", HFILL } },

        { &ofp_flow_mod_pad,
          { "Pad", "of.fm_pad", FT_UINT8, BASE_DEC, NO_STRINGS, NO_MASK, "Pad", HFILL } },

        { &ofp_flow_mod_reserved,
          { "Reserved", "of.fm_reserved", FT_UINT32, BASE_DEC, NO_STRINGS, NO_MASK, "Reserved", HFILL } },


        /* AM:  Flow Expired */
        { &ofp_flow_expired,
          { "Flow Expired", "of.fe", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Flow Expired", HFILL } },

        { &ofp_flow_expired_priority,
          { "Priority", "of.fe_priority", FT_UINT16, BASE_DEC, NO_STRINGS, NO_MASK, "Priority", HFILL } },

        { &ofp_flow_expired_pad,
          { "Pad", "of.fe_pad", FT_UINT8, BASE_DEC, NO_STRINGS, NO_MASK, "Pad", HFILL } },

        { &ofp_flow_expired_duration,
          { "Flow Duration (sec)", "of.fe_duration", FT_UINT32, BASE_DEC, NO_STRINGS, NO_MASK, "Time Flow was Alive (sec)", HFILL } },

        { &ofp_flow_expired_packet_count,
          { "Packet Count", "of.fe_packet_count", FT_UINT64, BASE_DEC, NO_STRINGS, NO_MASK, "Packet Cout", HFILL } },

        { &ofp_flow_expired_byte_count,
          { "Byte Count", "of.fe_byte_count", FT_UINT64, BASE_DEC, NO_STRINGS, NO_MASK, "Byte Count", HFILL } },


        /* CSM: Table */
        { &ofp_table_stats,
          { "Table Stats", "of.ts", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Table Stats", HFILL } },

        { &ofp_table_stats_table_id,
          { "Table ID", "of.ts_table_id", FT_UINT8, BASE_DEC, NO_STRINGS, NO_MASK, "Table ID", HFILL } },

        { &ofp_table_stats_pad,
          { "Pad", "of.ts_pad", FT_UINT8, BASE_DEC, NO_STRINGS, NO_MASK, "Pad", HFILL } },

        { &ofp_table_stats_name,
          { "Name", "of.ts_name", FT_STRING, BASE_NONE, NO_STRINGS, NO_MASK, "Name", HFILL } },

        { &ofp_table_stats_max_entries,
          { "Max Supported Entries", "of.ts_max_entries", FT_UINT32, BASE_DEC, NO_STRINGS, NO_MASK, "Max Supported Entries", HFILL } },

        { &ofp_table_stats_active_count,
          { "Active Entry Count", "of.ts_active_count", FT_UINT32, BASE_DEC, NO_STRINGS, NO_MASK, "Active Entry Count", HFILL } },

        { &ofp_table_stats_matched_count,
          { "Packet Match Count", "of.ts_match_count", FT_UINT64, BASE_DEC, NO_STRINGS, NO_MASK, "Packet Match Count", HFILL } },


        /* CSM: Port Mod */
        { &ofp_port_mod,
          { "Port Modification", "of.pm", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Port Modification", HFILL } },


        /* AM: Port Stats */
        { &ofp_port_stats,
          { "Port Stats", "of.ps", FT_NONE, BASE_NONE, NO_STRINGS, NO_MASK, "Port Stats", HFILL } },

        { &ofp_port_stats_port_no,
          { "Port #", "of.ps_port_no", FT_UINT16, BASE_DEC, NO_STRINGS, NO_MASK, "", HFILL } },

        { &ofp_port_stats_pad,
          { "Pad", "of.ps_pad", FT_UINT8, BASE_DEC, NO_STRINGS, NO_MASK, "", HFILL } },

        { &ofp_port_stats_rx_count,
          { "# Packets Recv  ", "of.ps_rx_count", FT_UINT64, BASE_DEC, NO_STRINGS, NO_MASK, "Number of Packets Received", HFILL } },

        { &ofp_port_stats_tx_count,
          { "# Packets Sent  ", "of.ps_tx_count", FT_UINT64, BASE_DEC, NO_STRINGS, NO_MASK, "Number of Packets Sent", HFILL } },

        { &ofp_port_stats_drop_count,
          { "# Packets Dropped", "of.ps_drop_count", FT_UINT64, BASE_DEC, NO_STRINGS, NO_MASK, "Number of Packets Dropped", HFILL } },


        /* CSM: Stats Request */

        /* CSM: Stats Reply */

        /* AM:  Error Message */

    };

    static gint *ett[] = {
        &ett_ofp,
        &ett_ofp_header,
        &ett_ofp_phy_port,
        &ett_ofp_phy_port_flags_hdr,
        &ett_ofp_phy_port_features_hdr,
        &ett_ofp_match,
        &ett_ofp_match_wildcards,
        &ett_ofp_action,
        &ett_ofp_action_output,
        &ett_ofp_switch_features,
        &ett_ofp_switch_features_table_info_hdr,
        &ett_ofp_switch_features_buffer_limits_hdr,
        &ett_ofp_switch_features_capabilities_hdr,
        &ett_ofp_switch_features_actions_hdr,
        &ett_ofp_switch_features_ports_hdr,
        &ett_ofp_switch_config,
        &ett_ofp_flow_mod,
        &ett_ofp_port_mod,
        &ett_ofp_stats_request,
        &ett_ofp_stats_reply,
        &ett_ofp_flow_stats_request,
        &ett_ofp_flow_stats,
        &ett_ofp_aggregate_stats_request,
        &ett_ofp_aggregate_stats_reply,
        &ett_ofp_table_stats,
        &ett_ofp_port_stats,
        &ett_ofp_packet_out,
        &ett_ofp_packet_out_data_hdr,
        &ett_ofp_packet_out_actions_hdr,
        &ett_ofp_packet_in,
        &ett_ofp_packet_in_data_hdr,
        &ett_ofp_flow_expired,
        &ett_ofp_port_status,
        &ett_ofp_error_msg,
    };

    proto_openflow = proto_register_protocol( "OpenFlow Protocol",
                                              "OPENFLOW",
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
 * Adds "hf" to "tree" starting at "offset" into "tvb" and using "length" bytes.
 */
static void add_child_const( proto_item* tree, gint hf, tvbuff_t *tvb, guint32 offset, guint32 len ) {
    proto_tree_add_item( tree, hf, tvb, offset, len, FALSE );
}

/** returns the length of a PDU which starts at the specified offset in tvb. */
static guint get_openflow_message_len(packet_info *pinfo, tvbuff_t *tvb, int offset) {
    return (guint)tvb_get_ntohs(tvb, offset+2); /* length is at offset 2 in the header */
}

static void dissect_phy_ports(proto_tree* tree, proto_item* item, tvbuff_t *tvb, packet_info *pinfo, guint32 *offset, guint num_ports)
{
    proto_item *port_item;
    proto_tree *port_tree;
    proto_item *flags_item;
    proto_tree *flags_tree;
    proto_item *features_item;
    proto_tree *features_tree;

    int i;
    while(num_ports-- > 0) {
        port_item = proto_tree_add_item(tree, ofp_phy_port, tvb, *offset, sizeof(struct ofp_phy_port), FALSE);
        port_tree = proto_item_add_subtree(port_item, ett_ofp_phy_port);

        add_child( port_tree, ofp_phy_port_port_no, tvb, offset, 2 );
        add_child( port_tree, ofp_phy_port_hw_addr, tvb, offset, 6 );
        add_child( port_tree, ofp_phy_port_name, tvb, offset, OFP_MAX_PORT_NAME_LEN );

        /* flags */
        flags_item = proto_tree_add_item(port_tree, ofp_phy_port_flags_hdr, tvb, *offset, 4, FALSE);
        flags_tree = proto_item_add_subtree(flags_item, ett_ofp_phy_port_flags_hdr);
        for(i=0; i<NUM_PORT_FLAGS; i++) {
            add_child_const(flags_tree, ofp_phy_port_flags[i], tvb, *offset, 4);
        }
        *offset += 4;

        add_child( port_tree, ofp_phy_port_speed, tvb, offset, 4 );

        /* features */
        features_item = proto_tree_add_item(port_tree, ofp_phy_port_features_hdr, tvb, *offset, 4, FALSE);
        features_tree = proto_item_add_subtree(features_item, ett_ofp_phy_port_features_hdr);
        for(i=0; i<NUM_PORT_FEATURES; i++) {
            add_child_const(features_tree, ofp_phy_port_features[i], tvb, *offset, 4);
        }
        *offset += 4;
    }
}

static void dissect_match(proto_tree* tree, proto_item* item, tvbuff_t *tvb, packet_info *pinfo, guint32 *offset)
{
    int i;
    proto_item *match_item = proto_tree_add_item(tree, ofp_match, tvb, *offset, sizeof(struct ofp_match), FALSE);
    proto_tree *match_tree = proto_item_add_subtree(match_item, ett_ofp_match);

    /* add wildcard subtree */
    guint16 wildcards = tvb_get_ntohs( tvb, *offset );
    proto_item *wild_item = proto_tree_add_item(match_tree, ofp_match_wildcards, tvb, *offset, 2, FALSE);
    proto_tree *wild_tree = proto_item_add_subtree(wild_item, ett_ofp_match_wildcards);
    for(i=0; i<NUM_WILDCARDS; i++)
        add_child_const(wild_tree, ofp_match_wildcard[i], tvb, *offset, 2 );
    *offset += 2;

    /* show only items whose corresponding wildcard bit is set */
    if( wildcards & OFPFW_IN_PORT )
        add_child(match_tree, ofp_match_in_port, tvb, offset, 2);
    else
        *offset += 2;

    if( wildcards & OFPFW_DL_SRC )
        add_child(match_tree, ofp_match_dl_src, tvb, offset, 6);
    else
        *offset += 6;

    if( wildcards & OFPFW_DL_DST )
        add_child(match_tree, ofp_match_dl_dst, tvb, offset, 6);
    else
        *offset += 6;

    if( wildcards & OFPFW_DL_VLAN )
        add_child(match_tree, ofp_match_dl_vlan, tvb, offset, 2);
    else
        *offset += 2;

    if( wildcards & OFPFW_DL_TYPE )
        add_child(match_tree, ofp_match_dl_type, tvb, offset, 2);
    else
        *offset += 2;

    if( wildcards & OFPFW_NW_SRC )
        add_child(match_tree, ofp_match_nw_src, tvb, offset, 4);
    else
        *offset += 4;

    if( wildcards & OFPFW_NW_DST )
        add_child(match_tree, ofp_match_nw_dst, tvb, offset, 4);
    else
        *offset += 4;

    if( wildcards & OFPFW_NW_PROTO )
        add_child(match_tree, ofp_match_nw_proto, tvb, offset, 1);
    else
        *offset += 1;

#if SHOW_PADDING
    add_child(match_tree, ofp_match_pad, tvb, offset, 1);
    add_child(match_tree, ofp_match_pad, tvb, offset, 1);
    add_child(match_tree, ofp_match_pad, tvb, offset, 1);
#else
    *offset += 3;
#endif

    if( wildcards & OFPFW_TP_SRC )
        add_child(match_tree, ofp_match_tp_src, tvb, offset, 2);
    else
        *offset += 2;

    if( wildcards & OFPFW_TP_DST )
        add_child(match_tree, ofp_match_tp_dst, tvb, offset, 2);
    else
        *offset += 2;
}

static void dissect_action_output(proto_tree* tree, tvbuff_t *tvb, guint32 *offset)
{
    /* determine the maximum number of bytes to send (0 =>  no limit) */
    guint16 max_bytes = tvb_get_ntohs( tvb, *offset );
    if( max_bytes ) {
        char str[11];
        snprintf( str, 11, "%u", max_bytes );
        add_child_str( tree, ofp_action_output_max_len, tvb, offset, 2, str );
    }
    else
        add_child_str( tree, ofp_action_output_max_len, tvb, offset, 2, "entire packet (no limit)" );



    /* add the output port */
    add_child( tree, ofp_action_output_port, tvb, offset, 2 );
}

/** returns the number of bytes dissected (-1 if an unknown action type is encountered) */
static gint dissect_action(proto_tree* tree, proto_item* item, tvbuff_t *tvb, packet_info *pinfo, guint32 *offset)
{
    int i;
    proto_item *action_item = proto_tree_add_item(tree, ofp_action, tvb, *offset, sizeof(struct ofp_action), FALSE);
    proto_tree *action_tree = proto_item_add_subtree(action_item, ett_ofp_action);

    guint16 type = tvb_get_ntohs( tvb, *offset );
    add_child( action_tree, ofp_action_type, tvb, offset, 2 );

    switch( type ) {
    case OFPAT_OUTPUT: {
        dissect_action_output(action_tree, tvb, offset);
        return 4;
    }

    case OFPAT_SET_DL_VLAN:
        add_child( action_tree, ofp_action_vlan_id, tvb, offset, 2 );
        return 2;

    case OFPAT_SET_DL_SRC:
    case OFPAT_SET_DL_DST:
        add_child( action_tree, ofp_action_dl_addr, tvb, offset, 6 );
        return 6;

    case OFPAT_SET_NW_SRC:
    case OFPAT_SET_NW_DST:
        add_child( action_tree, ofp_action_nw_addr, tvb, offset, 4 );
        return 4;

    case OFPAT_SET_TP_SRC:
    case OFPAT_SET_TP_DST:
        add_child( action_tree, ofp_action_tp, tvb, offset, 2 );
        return 2;

    default:
        add_child( action_tree, ofp_action_unknown, tvb, offset, 0 );
        return -1;
    }
}

static void dissect_action_array(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint len, guint offset)
{
    guint total_len = len - offset;
    proto_item* action_item = proto_tree_add_item(tree, ofp_action_output, tvb, offset, -1, FALSE);
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

static void dissect_capability_array(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset, guint field_size) {
    proto_item *sf_cap_item = proto_tree_add_item(tree, ofp_switch_features_capabilities_hdr, tvb, offset, field_size, FALSE);
    proto_tree *sf_cap_tree = proto_item_add_subtree(sf_cap_item, ett_ofp_switch_features_capabilities_hdr);
    gint i;
    for(i=0; i<NUM_CAPABILITIES; i++)
        add_child_const(sf_cap_tree, ofp_switch_features_capabilities[i], tvb, offset, field_size);
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

static void dissect_openflow_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
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

    /* clarify protocol name display with version, length, and type information */
    if (check_col(pinfo->cinfo, COL_INFO))
        col_add_fstr( pinfo->cinfo, COL_INFO,
                      "v0x%0X (%uB): %s",
                      ver, len, ofp_type_to_string(type) );

    if (tree) { /* we are being asked for details */
        proto_item *item        = NULL;
        proto_item *sub_item    = NULL;
        proto_tree *ofp_tree    = NULL;
        proto_tree *header_tree = NULL;
        guint32 offset = 0;
#       define STR_LEN 1024
        char str[STR_LEN];
        proto_item *type_item  = NULL;
        proto_tree *type_tree  = NULL;

        /* consume the entire tvb for the openflow packet, and add it to the tree */
        item = proto_tree_add_item(tree, proto_openflow, tvb, 0, -1, FALSE);
        ofp_tree = proto_item_add_subtree(item, ett_ofp);

        /* put the header in its own node as a child of the openflow node */
        sub_item = proto_tree_add_item( ofp_tree, ofp_header, tvb, offset, -1, FALSE );
        header_tree = proto_item_add_subtree(sub_item, ett_ofp_header);

        /* add a warning if the version is what the plugin was written to handle */
        if( ver != DISSECTOR_OPENFLOW_VERSION ) {
            snprintf( str, STR_LEN,
                      "Dissector written for OpenFlow v0x%0X (differs from this packet's version v0x%0X)",
                      DISSECTOR_OPENFLOW_VERSION, ver );
            add_child_str( header_tree, ofp_header_warn_ver, tvb, &offset, 0, str );
        }

        /* add the headers field as children of the header node */
        add_child( header_tree, ofp_header_version, tvb, &offset, 1 );
        add_child( header_tree, ofp_header_type,    tvb, &offset, 1 );
        add_child( header_tree, ofp_header_length,  tvb, &offset, 2 );
        add_child( header_tree, ofp_header_xid,     tvb, &offset, 4 );

        switch( type ) {
        case OFPT_FEATURES_REQUEST:
            /* nothing else in this packet type */
            break;

        case OFPT_FEATURES_REPLY: {
            proto_item *sf_ti_item = NULL;
            proto_tree *sf_ti_tree = NULL;
            proto_item *sf_bl_item = NULL;
            proto_tree *sf_bl_tree = NULL;
            proto_item *sf_act_item = NULL;
            proto_tree *sf_act_tree = NULL;
            proto_item *sf_port_item = NULL;
            proto_tree *sf_port_tree = NULL;
            guint i, num_ports;
            gint sz;

            type_item = proto_tree_add_item(ofp_tree, ofp_switch_features, tvb, offset, -1, FALSE);
            type_tree = proto_item_add_subtree(type_item, ett_ofp_switch_features);

            /* fields we'll put directly in the subtree */
            add_child(type_tree, ofp_switch_features_datapath_id, tvb, &offset, 8);

            /* Table info */
            sf_ti_item = proto_tree_add_item(type_tree, ofp_switch_features_table_info_hdr, tvb, offset, 12, FALSE);
            sf_ti_tree = proto_item_add_subtree(sf_ti_item, ett_ofp_switch_features_table_info_hdr);
            add_child(sf_ti_tree, ofp_switch_features_n_exact, tvb, &offset, 4);
            add_child(sf_ti_tree, ofp_switch_features_n_compression, tvb, &offset, 4);
            add_child(sf_ti_tree, ofp_switch_features_n_general, tvb, &offset, 4);

            /* Buffer limits */
            sf_bl_item = proto_tree_add_item(type_tree, ofp_switch_features_buffer_limits_hdr, tvb, offset, 8, FALSE);
            sf_bl_tree = proto_item_add_subtree(sf_bl_item, ett_ofp_switch_features_buffer_limits_hdr);
            add_child(sf_bl_tree, ofp_switch_features_buffer_mb, tvb, &offset, 4);
            add_child(sf_bl_tree, ofp_switch_features_n_buffers, tvb, &offset, 4);

            /* capabilities */
            dissect_capability_array(tvb, pinfo, type_tree, offset, 4);
            offset += 4;

            /* actions */
            sf_act_item = proto_tree_add_item(type_tree, ofp_switch_features_actions_hdr, tvb, offset, 4, FALSE);
            sf_act_tree = proto_item_add_subtree(sf_act_item, ett_ofp_switch_features_actions_hdr);
            if( ver < 0x90 ) {
                /* add warning: meaningless until v0x90 */
                add_child_const(sf_act_tree, ofp_switch_features_actions_warn, tvb, offset, 4);
            }
            for(i=0; i<NUM_ACTIONS; i++) {
                add_child_const(sf_act_tree, ofp_switch_features_actions[i], tvb, offset, 4);
            }
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
            dissect_capability_array(tvb, pinfo, type_tree, offset, 2);
            offset += 2;
            add_child(type_tree, ofp_switch_config_miss_send_len, tvb, &offset, 2);
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
#if SHOW_PADDING
            add_child(type_tree, ofp_packet_in_pad, tvb, &offset, 1);
#else
            offset += 1;
#endif

            /* continue the dissection with the Ethernet dissector */
            if( data_ethernet ) {
                proto_item *data_item = proto_tree_add_item(type_tree, ofp_packet_in_data_hdr, tvb, offset, -1, FALSE);
                proto_tree *data_tree = proto_item_add_subtree(data_item, ett_ofp_packet_in_data_hdr);
                tvbuff_t *next_tvb = tvb_new_subset(tvb, offset, -1, total_len);
                dissect_ethernet(next_tvb, pinfo, data_tree);
            }
            else {
                /* if we couldn't load the ethernet dissector, just display the bytes */
                add_child(type_tree, ofp_packet_in_data_hdr, tvb, &offset, total_len);
            }

            break;
        }

        case OFPT_PACKET_OUT: {
            type_item = proto_tree_add_item(ofp_tree, ofp_packet_out, tvb, offset, -1, FALSE);
            type_tree = proto_item_add_subtree(type_item, ett_ofp_packet_out);

            /* explicitly pull out the buffer id so we can use it to determine
               what the last field is */
            guint32 buffer_id = tvb_get_ntohl( tvb, offset );
            if( buffer_id == 0xFFFFFFFF )
                add_child_str(type_tree, ofp_packet_out_buffer_id, tvb, &offset, 4, "-1");
            else {
                snprintf(str, STR_LEN, "%u", buffer_id);
                add_child_str(type_tree, ofp_packet_out_buffer_id, tvb, &offset, 4, str);
            }

            /* check whether in_port exists */
            guint16 in_port = tvb_get_ntohs( tvb, offset );
            if( in_port == OFPP_NONE )
                add_child_str(type_tree, ofp_packet_out_in_port, tvb, &offset, 2, "none");
            else {
                snprintf(str, STR_LEN, "%u", in_port);
                add_child_str(type_tree, ofp_packet_out_in_port, tvb, &offset, 2, str);
            }

            add_child(type_tree, ofp_packet_out_out_port, tvb, &offset, 2);

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
            else {
                /* handle actions */
                dissect_action_array(tvb, pinfo, type_tree, len, offset);
            }

            break;
        }

        case OFPT_FLOW_MOD: {
            type_item = proto_tree_add_item(ofp_tree, ofp_flow_mod, tvb, offset, -1, FALSE);
            type_tree = proto_item_add_subtree(type_item, ett_ofp_flow_mod);

            dissect_match(type_tree, type_item, tvb, pinfo, &offset);
            add_child(type_tree, ofp_flow_mod_command, tvb, &offset, 2);
            add_child(type_tree, ofp_flow_mod_max_idle, tvb, &offset, 2);
            add_child(type_tree, ofp_flow_mod_buffer_id, tvb, &offset, 4);
            add_child(type_tree, ofp_flow_mod_priority, tvb, &offset, 2);
#if SHOW_PADDING
            add_child(type_tree, ofp_flow_mod_pad, tvb, &offset, 1);
            add_child(type_tree, ofp_flow_mod_pad, tvb, &offset, 1);
#else
            offset += 2;
#endif
            add_child(type_tree, ofp_flow_mod_reserved, tvb, &offset, 4);
            dissect_action_array(tvb, pinfo, type_tree, len, offset);
            break;
        }

        case OFPT_FLOW_EXPIRED: {
            type_item = proto_tree_add_item(ofp_tree, ofp_flow_expired, tvb, offset, -1, FALSE);
            type_tree = proto_item_add_subtree(type_item, ett_ofp_flow_expired);

            dissect_match(type_tree, type_item, tvb, pinfo, &offset);
            add_child(type_tree, ofp_flow_expired_priority, tvb, &offset, 2);
#if SHOW_PADDING
            add_child(type_tree, ofp_flow_expired_pad, tvb, &offset, 1);
            add_child(type_tree, ofp_flow_expired_pad, tvb, &offset, 1);
#else
            offset += 2;
#endif
            add_child(type_tree, ofp_flow_expired_duration, tvb, &offset, 4);
            add_child(type_tree, ofp_flow_expired_packet_count, tvb, &offset, 8);
            add_child(type_tree, ofp_flow_expired_byte_count, tvb, &offset, 8);
            break;
        }

        case OFPT_TABLE: {
            type_item = proto_tree_add_item(ofp_tree, ofp_table_stats, tvb, offset, -1, FALSE);
            type_tree = proto_item_add_subtree(type_item, ett_ofp_table_stats);

            add_child(type_tree, ofp_table_stats_table_id, tvb, &offset, 1);
#if SHOW_PADDING
            add_child(type_tree, ofp_table_stats_pad, tvb, &offset, 1);
            add_child(type_tree, ofp_table_stats_pad, tvb, &offset, 1);
            add_child(type_tree, ofp_table_stats_pad, tvb, &offset, 1);
#else
            offset += 3;
#endif
            add_child(type_tree, ofp_table_stats_name, tvb, &offset, OFP_MAX_TABLE_NAME_LEN);
            add_child(type_tree, ofp_table_stats_max_entries, tvb, &offset, 4);
            add_child(type_tree, ofp_table_stats_active_count, tvb, &offset, 4);
            add_child(type_tree, ofp_table_stats_matched_count, tvb, &offset, 8);
            break;
        }

        case OFPT_PORT_MOD: {
            type_item = proto_tree_add_item(ofp_tree, ofp_port_mod, tvb, offset, -1, FALSE);
            type_tree = proto_item_add_subtree(type_item, ett_ofp_port_mod);
            dissect_phy_ports(type_tree, type_item, tvb, pinfo, &offset, 1);
            break;
        }

        case OFPT_PORT_STATUS: {
            type_item = proto_tree_add_item(ofp_tree, ofp_port_stats, tvb, offset, -1, FALSE);
            type_tree = proto_item_add_subtree(type_item, ett_ofp_port_stats);

            add_child(type_tree, ofp_port_stats_port_no, tvb, &offset, 2);
#if SHOW_PADDING
            add_child(type_tree, ofp_port_stats_pad, tvb, &offset, 1);
            add_child(type_tree, ofp_port_stats_pad, tvb, &offset, 1);
#else
            offset += 2;
#endif
            add_child(type_tree, ofp_port_stats_rx_count, tvb, &offset, 8);
            add_child(type_tree, ofp_port_stats_tx_count, tvb, &offset, 8);
            add_child(type_tree, ofp_port_stats_drop_count, tvb, &offset, 8);
            break;
        }

        case OFPT_STATS_REQUEST:

            break;

        case OFPT_STATS_REPLY:

            break;

        case OFPT_ERROR_MSG:

            break;

        default:
            /* add a warning if we encounter an unrecognized packet type */
            snprintf(str, STR_LEN, "Dissector does not recognize type %u", type);
            add_child_str(tree, ofp_header_warn_type, tvb, &offset, 0, str);
        }
    }
}

static void dissect_openflow(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    /* have wireshark reassemble our PDUs; call dissect_openflow_when full PDU assembled */
    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 4, get_openflow_message_len, dissect_openflow_message);
}
