/**
 * Filename: packet-openflow.c
 * Author:   David Underhill
 * Updated:  2008-Jul-10
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

/** names from ofp_capabilities */
static const value_string names_ofp_capabilities[] = {
    { OFPC_FLOW_STATS,   "Flow statistics" },
    { OFPC_TABLE_STATS,  "Table statistics" },
    { OFPC_PORT_STATS,   "Port statistics" },
    { OFPC_STP,          "802.11d spanning tree" },
    { OFPC_MULTI_PHY_TX, "Supports transmitting through multiple physical interface" },
    { 0,                 NULL }
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
static gint ofp_phy_port_flags    = -1;
static gint ofp_phy_port_speed    = -1;
static gint ofp_phy_port_features = -1;

static gint ofp_match           = -1;
static gint ofp_match_wildcards = -1;
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

static gint ofp_action         = -1;
static gint ofp_action_type    = -1;
static gint ofp_action_output  = -1;
static gint ofp_action_vlan_id = -1;
static gint ofp_action_dl_addr = -1;
static gint ofp_action_nw_addr = -1;
static gint ofp_action_tp      = -1;

/* type: ofp_action_output */
static gint ofp_action_output_max_len = -1;
static gint ofp_action_output_port    = -1;

/* Controller/Switch Messages */
static gint ofp_switch_features               = -1;
static gint ofp_switch_features_datapath_id   = -1;
static gint ofp_switch_features_n_exact       = -1;
static gint ofp_switch_features_n_compression = -1;
static gint ofp_switch_features_n_general     = -1;
static gint ofp_switch_features_buffer_mb     = -1;
static gint ofp_switch_features_n_buffers     = -1;
static gint ofp_switch_features_capabilities  = -1;
static gint ofp_switch_features_actions       = -1;
static gint ofp_switch_features_ports         = -1;

static gint ofp_switch_config               = -1;
static gint ofp_switch_config_flags         = -1;
static gint ofp_switch_config_miss_send_len = -1;

static gint ofp_flow_mod           = -1;
static gint ofp_flow_mod_match     = -1;
static gint ofp_flow_mod_command   = -1;
static gint ofp_flow_mod_max_idle  = -1;
static gint ofp_flow_mod_buffer_id = -1;
static gint ofp_flow_mod_priority  = -1;
static gint ofp_flow_mod_pad       = -1;
static gint ofp_flow_mod_reserved  = -1;
static gint ofp_flow_mod_actions   = -1;

static gint ofp_port_mod      = -1;
static gint ofp_port_mod_desc = -1;

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
static gint ofp_packet_out_actions   = -1;
static gint ofp_packet_out_data      = -1;

/* Asynchronous Messages */
static gint ofp_packet_in        = -1;
static gint ofp_packet_buffer_id = -1;
static gint ofp_packet_total_len = -1;
static gint ofp_packet_in_port   = -1;
static gint ofp_packet_reason    = -1;
static gint ofp_packet_pad       = -1;
static gint ofp_packet_data      = -1;

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
static gint ett_ofp                = -1;

/* Open Flow Header */
static gint ett_ofp_header         = -1;
static gint ett_ofp_header_version = -1;
static gint ett_ofp_header_type    = -1;
static gint ett_ofp_header_length  = -1;
static gint ett_ofp_header_xid     = -1;
static gint ett_ofp_header_warn_ver = -1;
static gint ett_ofp_header_warn_type = -1;

/* Common Structures */
static gint ett_ofp_phy_port          = -1;
static gint ett_ofp_phy_port_port_no  = -1;
static gint ett_ofp_phy_port_hw_addr  = -1;
static gint ett_ofp_phy_port_name     = -1;
static gint ett_ofp_phy_port_flags    = -1;
static gint ett_ofp_phy_port_speed    = -1;
static gint ett_ofp_phy_port_features = -1;

static gint ett_ofp_match           = -1;
static gint ett_ofp_match_wildcards = -1;
static gint ett_ofp_match_in_port   = -1;
static gint ett_ofp_match_dl_src    = -1;
static gint ett_ofp_match_dl_dst    = -1;
static gint ett_ofp_match_dl_vlan   = -1;
static gint ett_ofp_match_dl_type   = -1;
static gint ett_ofp_match_nw_src    = -1;
static gint ett_ofp_match_nw_dst    = -1;
static gint ett_ofp_match_nw_proto  = -1;
static gint ett_ofp_match_pad       = -1;
static gint ett_ofp_match_tp_src    = -1;
static gint ett_ofp_match_tp_dst    = -1;

static gint ett_ofp_action         = -1;
static gint ett_ofp_action_type    = -1;
static gint ett_ofp_action_output  = -1;
static gint ett_ofp_action_vlan_id = -1;
static gint ett_ofp_action_dl_addr = -1;
static gint ett_ofp_action_nw_addr = -1;
static gint ett_ofp_action_tp      = -1;

static gint ett_ofp_action_output_max_len = -1;
static gint ett_ofp_action_output_port    = -1;

/* Controller/Switch Messages */
static gint ett_ofp_switch_features               = -1;
static gint ett_ofp_switch_features_datapath_id   = -1;
static gint ett_ofp_switch_features_n_exact       = -1;
static gint ett_ofp_switch_features_n_compression = -1;
static gint ett_ofp_switch_features_n_general     = -1;
static gint ett_ofp_switch_features_buffer_mb     = -1;
static gint ett_ofp_switch_features_n_buffers     = -1;
static gint ett_ofp_switch_features_capabilities  = -1;
static gint ett_ofp_switch_features_actions       = -1;
static gint ett_ofp_switch_features_ports         = -1;

static gint ett_ofp_switch_config               = -1;
static gint ett_ofp_switch_config_flags         = -1;
static gint ett_ofp_switch_config_miss_send_len = -1;

static gint ett_ofp_flow_mod           = -1;
static gint ett_ofp_flow_mod_match     = -1;
static gint ett_ofp_flow_mod_command   = -1;
static gint ett_ofp_flow_mod_max_idle  = -1;
static gint ett_ofp_flow_mod_buffer_id = -1;
static gint ett_ofp_flow_mod_priority  = -1;
static gint ett_ofp_flow_mod_pad       = -1;
static gint ett_ofp_flow_mod_reserved  = -1;
static gint ett_ofp_flow_mod_actions   = -1;

static gint ett_ofp_port_mod      = -1;
static gint ett_ofp_port_mod_desc = -1;

static gint ett_ofp_stats_request       = -1;
static gint ett_ofp_stats_request_type  = -1;
static gint ett_ofp_stats_request_flags = -1;
static gint ett_ofp_stats_request_body  = -1;

static gint ett_ofp_stats_reply       = -1;
static gint ett_ofp_stats_reply_type  = -1;
static gint ett_ofp_stats_reply_flags = -1;
static gint ett_ofp_stats_reply_body  = -1;

static gint ett_ofp_flow_stats_request          = -1;
/* field: ett_ofp_match */
static gint ett_ofp_flow_stats_request_table_id = -1;
static gint ett_ofp_flow_stats_request_pad      = -1;

static gint ett_ofp_flow_stats              = -1;
static gint ett_ofp_flow_stats_length       = -1;
static gint ett_ofp_flow_stats_table_id     = -1;
static gint ett_ofp_flow_stats_pad          = -1;
static gint ett_ofp_flow_stats_match        = -1;
static gint ett_ofp_flow_stats_duration     = -1;
static gint ett_ofp_flow_stats_packet_count = -1;
static gint ett_ofp_flow_stats_byte_count   = -1;
static gint ett_ofp_flow_stats_priority     = -1;
static gint ett_ofp_flow_stats_max_idle     = -1;
static gint ett_ofp_flow_stats_actions      = -1;

static gint ett_ofp_aggregate_stats_request          = -1;
/* field: ett_ofp_match */
static gint ett_ofp_aggregate_stats_request_table_id = -1;
static gint ett_ofp_aggregate_stats_request_pad      = -1;

static gint ett_ofp_aggregate_stats_reply              = -1;
static gint ett_ofp_aggregate_stats_reply_packet_count = -1;
static gint ett_ofp_aggregate_stats_reply_byte_count   = -1;
static gint ett_ofp_aggregate_stats_reply_flow_count   = -1;

static gint ett_ofp_table_stats               = -1;
static gint ett_ofp_table_stats_table_id      = -1;
static gint ett_ofp_table_stats_pad           = -1;
static gint ett_ofp_table_stats_name          = -1;
static gint ett_ofp_table_stats_max_entries   = -1;
static gint ett_ofp_table_stats_active_count  = -1;
static gint ett_ofp_table_stats_matched_count = -1;

static gint ett_ofp_port_stats            = -1;
static gint ett_ofp_port_stats_port_no    = -1;
static gint ett_ofp_port_stats_pad        = -1;
static gint ett_ofp_port_stats_rx_count   = -1;
static gint ett_ofp_port_stats_tx_count   = -1;
static gint ett_ofp_port_stats_drop_count = -1;

static gint ett_ofp_packet_out           = -1;
static gint ett_ofp_packet_out_buffer_id = -1;
static gint ett_ofp_packet_out_in_port   = -1;
static gint ett_ofp_packet_out_out_port  = -1;
static gint ett_ofp_packet_out_actions   = -1;
static gint ett_ofp_packet_out_data      = -1;

/* Asynchronous Messages */
static gint ett_ofp_packet_in        = -1;
static gint ett_ofp_packet_buffer_id = -1;
static gint ett_ofp_packet_total_len = -1;
static gint ett_ofp_packet_in_port   = -1;
static gint ett_ofp_packet_reason    = -1;
static gint ett_ofp_packet_pad       = -1;
static gint ett_ofp_packet_data      = -1;

static gint ett_ofp_flow_expired              = -1;
/* field: ett_ofp_match */
static gint ett_ofp_flow_expired_priority     = -1;
static gint ett_ofp_flow_expired_pad          = -1;
static gint ett_ofp_flow_expired_duration     = -1;
static gint ett_ofp_flow_expired_packet_count = -1;
static gint ett_ofp_flow_expired_byte_count   = -1;

static gint ett_ofp_port_status        = -1;
static gint ett_ofp_port_status_reason = -1;
static gint ett_ofp_port_status_pad    = -1;
static gint ett_ofp_port_status_desc   = -1;

static gint ett_ofp_error_msg      = -1;
static gint ett_ofp_error_msg_type = -1;
static gint ett_ofp_error_msg_code = -1;
static gint ett_ofp_error_msg_data = -1;

void proto_reg_handoff_openflow()
{
    openflow_handle = create_dissector_handle(dissect_openflow, proto_openflow);
    dissector_add(TCP_PORT_FILTER, global_openflow_proto, openflow_handle);
}

#define NO_STRINGS NULL
#define NO_MASK 0x0

void proto_register_openflow()
{
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

        /* CSM: Features Request */
        /* nothing beyond the header */

        /* CSM: Features Reply */

        /* CSM: Get Config Request */

        /* CSM: Get Config Reply */

        /* CSM: Set Config */

        /* AM:  Packet In */

        /* CSM: Packet Out */

        /* CSM: Flow Mod */

        /* AM:  Flow Expired */

        /* CSM: Table */

        /* CSM: Port Mod */

        /* AM:  Port Status */

        /* CSM: Stats Request */

        /* CSM: Stats Reply */

        /* AM:  Error Message */

    };

    static gint *ett[] = {
        &ett_ofp,
        &ett_ofp_header,
        &ett_ofp_header_version,
        &ett_ofp_header_type,
        &ett_ofp_header_length,
        &ett_ofp_header_xid,
        &ett_ofp_header_warn_ver,
        &ett_ofp_header_warn_type,
        &ett_ofp_phy_port,
        &ett_ofp_phy_port_port_no,
        &ett_ofp_phy_port_hw_addr,
        &ett_ofp_phy_port_name,
        &ett_ofp_phy_port_flags,
        &ett_ofp_phy_port_speed,
        &ett_ofp_phy_port_features,
        &ett_ofp_match,
        &ett_ofp_match_wildcards,
        &ett_ofp_match_in_port,
        &ett_ofp_match_dl_src,
        &ett_ofp_match_dl_dst,
        &ett_ofp_match_dl_vlan,
        &ett_ofp_match_dl_type,
        &ett_ofp_match_nw_src,
        &ett_ofp_match_nw_dst,
        &ett_ofp_match_nw_proto,
        &ett_ofp_match_pad,
        &ett_ofp_match_tp_src,
        &ett_ofp_match_tp_dst,
        &ett_ofp_action,
        &ett_ofp_action_type,
        &ett_ofp_action_output,
        &ett_ofp_action_vlan_id,
        &ett_ofp_action_dl_addr,
        &ett_ofp_action_nw_addr,
        &ett_ofp_action_tp,
        &ett_ofp_action_output_max_len,
        &ett_ofp_action_output_port,
        &ett_ofp_switch_features,
        &ett_ofp_switch_features_datapath_id,
        &ett_ofp_switch_features_n_exact,
        &ett_ofp_switch_features_n_compression,
        &ett_ofp_switch_features_n_general,
        &ett_ofp_switch_features_buffer_mb,
        &ett_ofp_switch_features_n_buffers,
        &ett_ofp_switch_features_capabilities,
        &ett_ofp_switch_features_actions,
        &ett_ofp_switch_features_ports,
        &ett_ofp_switch_config,
        &ett_ofp_switch_config_flags,
        &ett_ofp_switch_config_miss_send_len,
        &ett_ofp_flow_mod,
        &ett_ofp_flow_mod_match,
        &ett_ofp_flow_mod_command,
        &ett_ofp_flow_mod_max_idle,
        &ett_ofp_flow_mod_buffer_id,
        &ett_ofp_flow_mod_priority,
        &ett_ofp_flow_mod_pad,
        &ett_ofp_flow_mod_reserved,
        &ett_ofp_flow_mod_actions,
        &ett_ofp_port_mod,
        &ett_ofp_port_mod_desc,
        &ett_ofp_stats_request,
        &ett_ofp_stats_request_type,
        &ett_ofp_stats_request_flags,
        &ett_ofp_stats_request_body,
        &ett_ofp_stats_reply,
        &ett_ofp_stats_reply_type,
        &ett_ofp_stats_reply_flags,
        &ett_ofp_stats_reply_body,
        &ett_ofp_flow_stats_request,
        &ett_ofp_flow_stats_request_table_id,
        &ett_ofp_flow_stats_request_pad,
        &ett_ofp_flow_stats,
        &ett_ofp_flow_stats_length,
        &ett_ofp_flow_stats_table_id,
        &ett_ofp_flow_stats_pad,
        &ett_ofp_flow_stats_match,
        &ett_ofp_flow_stats_duration,
        &ett_ofp_flow_stats_packet_count,
        &ett_ofp_flow_stats_byte_count,
        &ett_ofp_flow_stats_priority,
        &ett_ofp_flow_stats_max_idle,
        &ett_ofp_flow_stats_actions,
        &ett_ofp_aggregate_stats_request,
        &ett_ofp_aggregate_stats_request_table_id,
        &ett_ofp_aggregate_stats_request_pad,
        &ett_ofp_aggregate_stats_reply,
        &ett_ofp_aggregate_stats_reply_packet_count,
        &ett_ofp_aggregate_stats_reply_byte_count,
        &ett_ofp_aggregate_stats_reply_flow_count,
        &ett_ofp_table_stats,
        &ett_ofp_table_stats_table_id,
        &ett_ofp_table_stats_pad,
        &ett_ofp_table_stats_name,
        &ett_ofp_table_stats_max_entries,
        &ett_ofp_table_stats_active_count,
        &ett_ofp_table_stats_matched_count,
        &ett_ofp_port_stats,
        &ett_ofp_port_stats_port_no,
        &ett_ofp_port_stats_pad,
        &ett_ofp_port_stats_rx_count,
        &ett_ofp_port_stats_tx_count,
        &ett_ofp_port_stats_drop_count,
        &ett_ofp_packet_out,
        &ett_ofp_packet_out_buffer_id,
        &ett_ofp_packet_out_in_port,
        &ett_ofp_packet_out_out_port,
        &ett_ofp_packet_out_actions,
        &ett_ofp_packet_out_data,
        &ett_ofp_packet_in,
        &ett_ofp_packet_buffer_id,
        &ett_ofp_packet_total_len,
        &ett_ofp_packet_in_port,
        &ett_ofp_packet_reason,
        &ett_ofp_packet_pad,
        &ett_ofp_packet_data,
        &ett_ofp_flow_expired,
        &ett_ofp_flow_expired_priority,
        &ett_ofp_flow_expired_pad,
        &ett_ofp_flow_expired_duration,
        &ett_ofp_flow_expired_packet_count,
        &ett_ofp_flow_expired_byte_count,
        &ett_ofp_port_status,
        &ett_ofp_port_status_reason,
        &ett_ofp_port_status_pad,
        &ett_ofp_port_status_desc,
        &ett_ofp_error_msg,
        &ett_ofp_error_msg_type,
        &ett_ofp_error_msg_code,
        &ett_ofp_error_msg_data
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

static void dissect_openflow_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    /* display our protocol text if the protocol column is visible */
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
        col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_OPENFLOW);

    /* Clear out stuff in the info column */
    if(check_col(pinfo->cinfo,COL_INFO)){
        col_clear(pinfo->cinfo,COL_INFO);
    }

    /* get some of the header fields' values for later use */
    guint8  ver  = tvb_get_guint8( tvb, 0 );
    guint8  type = tvb_get_guint8( tvb, 1 );
    guint16 len  = tvb_get_ntohs(  tvb, 2 );

    /* clarify protocol name display with version, length, and type information */
    if (check_col(pinfo->cinfo, COL_INFO)) {
        col_add_fstr( pinfo->cinfo, COL_INFO,
                      "v0x%0X (%uB): %s",
                      ver, len, ofp_type_to_string(type) );
    }

    if (tree) { /* we are being asked for details */
        proto_item *item        = NULL;
        proto_item *sub_item    = NULL;
        proto_tree *ofp_tree     = NULL;
        proto_tree *header_tree = NULL;
        guint32 offset = 0;
#       define STR_LEN 1024
        char str[STR_LEN];

        /* consume the entire tvb for the openflow packet, and add it to the tree */
        item = proto_tree_add_item(tree, proto_openflow, tvb, 0, -1, FALSE);
        ofp_tree = proto_item_add_subtree(item, ett_ofp);
        header_tree = proto_item_add_subtree(item, ett_ofp);

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

            break;

        case OFPT_FEATURES_REPLY:

            break;

        case OFPT_GET_CONFIG_REQUEST:

            break;

        case OFPT_GET_CONFIG_REPLY:

            break;

        case OFPT_SET_CONFIG:

            break;

        case OFPT_PACKET_IN:

            break;

        case OFPT_PACKET_OUT:

            break;

        case OFPT_FLOW_MOD:

            break;

        case OFPT_FLOW_EXPIRED:

            break;

        case OFPT_TABLE:

            break;

        case OFPT_PORT_MOD:

            break;

        case OFPT_PORT_STATUS:

            break;

        case OFPT_STATS_REQUEST:

            break;

        case OFPT_STATS_REPLY:

            break;

        case OFPT_ERROR_MSG:

            break;

        default:
            /* add a warning if we encounter an unrecognized packet type */
            snprintf( str, STR_LEN, "Dissector does not recognize type %u", type );
            add_child_str( header_tree, ofp_header_warn_type, tvb, &offset, 0, str );
        }
    }
}

static void dissect_openflow(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    /* have wireshark reassemble our PDUs; call dissect_openflow_when full PDU assembled */
    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 4, get_openflow_message_len, dissect_openflow_message);
}
