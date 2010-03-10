/********************************************************
*
* C register defines file for openflow_switch
*
********************************************************/

#ifndef _REG_DEFINES_
#define _REG_DEFINES_

/* ========= Constants ========= */

// ===== File: lib/verilog/core/common/xml/global.xml =====

// Maximum number of phy ports
#define MAX_PHY_PORTS                             4

// PCI address bus width
#define PCI_ADDR_WIDTH                            32

// PCI data bus width
#define PCI_DATA_WIDTH                            32

// PCI byte enable bus width
#define PCI_BE_WIDTH                              4

// CPCI--CNET address bus width. This is byte addresses even though bottom bits are zero.
#define CPCI_CNET_ADDR_WIDTH                      27

// CPCI--CNET data bus width
#define CPCI_CNET_DATA_WIDTH                      32

// CPCI--NF2 address bus width. This is byte addresses even though bottom bits are zero.
#define CPCI_NF2_ADDR_WIDTH                       27

// CPCI--NF2 data bus width
#define CPCI_NF2_DATA_WIDTH                       32

// DMA data bus width
#define DMA_DATA_WIDTH                            32

// DMA control bus width
#define DMA_CTRL_WIDTH                            4

// CPCI debug bus width
#define CPCI_DEBUG_DATA_WIDTH                     29

// SRAM address width
#define SRAM_ADDR_WIDTH                           19

// SRAM data width
#define SRAM_DATA_WIDTH                           36

// DRAM address width
#define DRAM_ADDR_WIDTH                           24

// ===== File: lib/verilog/core/common/xml/nf_defines.xml =====

// Clock period of 125 MHz clock in ns
#define FAST_CLK_PERIOD                           8

// Clock period of 62.5 MHz clock in ns
#define SLOW_CLK_PERIOD                           16

// Header value used by the IO queues
#define IO_QUEUE_STAGE_NUM                        0xff

// Data path data width
#define DATA_WIDTH                                64

// Data path control width
#define CTRL_WIDTH                                8

// ===== File: projects/openflow_switch/include/output_port_lookup.xml =====

#define FAST_CLOCK_PERIOD                         8

// ===== File: projects/openflow_switch/include/vlan_remover.xml =====

#define VLAN_CTRL_WORD                            0x42

#define VLAN_ETHERTYPE                            0x8100

// ===== File: lib/verilog/core/output_queues/bram_output_queues/xml/bram_output_queues.xml =====

#define NUM_OUTPUT_QUEUES                         8

// ===== File: projects/openflow_switch/include/opl_processor.xml =====

#define NF2_OFPAT_OUTPUT                          0x0001

#define NF2_OFPAT_SET_VLAN_VID                    0x0002

#define NF2_OFPAT_SET_VLAN_PCP                    0x0004

#define NF2_OFPAT_STRIP_VLAN                      0x0008

#define NF2_OFPAT_SET_DL_SRC                      0x0010

#define NF2_OFPAT_SET_DL_DST                      0x0020

#define NF2_OFPAT_SET_NW_SRC                      0x0040

#define NF2_OFPAT_SET_NW_DST                      0x0080

#define NF2_OFPAT_SET_TP_SRC                      0x0100

#define NF2_OFPAT_SET_TP_DST                      0x0200

// ===== File: projects/openflow_switch/include/wildcard_match.xml =====

#define OPENFLOW_WILDCARD_TABLE_SIZE              32

#define OPENFLOW_WILDCARD_NUM_DATA_WORDS_USED     10

#define OPENFLOW_WILDCARD_NUM_CMP_WORDS_USED      8

// ===== File: lib/verilog/core/utils/xml/device_id_reg.xml =====

// Total number of registers
#define DEV_ID_NUM_REGS                           32

// Number of non string registers
#define DEV_ID_NON_DEV_STR_REGS                   7

// Device description length (in words, not chars)
#define DEV_ID_DEV_STR_WORD_LEN                   25

// Device description length (in bytes/chars)
#define DEV_ID_DEV_STR_BYTE_LEN                   100

// Device description length (in bits)
#define DEV_ID_DEV_STR_BIT_LEN                    800

// Length of MD5 sum (bits)
#define DEV_ID_MD5SUM_LENGTH                      128

// MD5 sum of the string "device_id.v"
#define DEV_ID_MD5_VALUE                          0x4071736d8a603d2b4d55f62989a73c95
#define DEV_ID_MD5_VALUE_0                        0x4071736d
#define DEV_ID_MD5_VALUE_1                        0x8a603d2b
#define DEV_ID_MD5_VALUE_2                        0x4d55f629
#define DEV_ID_MD5_VALUE_3                        0x89a73c95

// ===== File: projects/openflow_switch/include/header_parser.xml =====

#define ETH_TYPE_IP                               0x0800

#define IP_PROTO_TCP                              0x06

#define IP_PROTO_UDP                              0x11

#define IP_PROTO_ICMP                             0x01

// ===== File: projects/openflow_switch/include/watchdog.xml =====

#define WDT_CPCI_REG_CTRL                         0x00000008

// ===== File: lib/verilog/core/io_queues/ethernet_mac/xml/ethernet_mac.xml =====

// TX queue disable bit
#define MAC_GRP_TX_QUEUE_DISABLE_BIT_NUM          0

// RX queue disable bit
#define MAC_GRP_RX_QUEUE_DISABLE_BIT_NUM          1

// Reset MAC bit
#define MAC_GRP_RESET_MAC_BIT_NUM                 2

// MAC TX queue disable bit
#define MAC_GRP_MAC_DISABLE_TX_BIT_NUM            3

// MAC RX queue disable bit
#define MAC_GRP_MAC_DISABLE_RX_BIT_NUM            4

// MAC disable jumbo TX bit
#define MAC_GRP_MAC_DIS_JUMBO_TX_BIT_NUM          5

// MAC disable jumbo RX bit
#define MAC_GRP_MAC_DIS_JUMBO_RX_BIT_NUM          6

// MAC disable crc check disable bit
#define MAC_GRP_MAC_DIS_CRC_CHECK_BIT_NUM         7

// MAC disable crc generate bit
#define MAC_GRP_MAC_DIS_CRC_GEN_BIT_NUM           8

// ===== File: projects/openflow_switch/include/match_arbiter.xml =====

#define OPENFLOW_ENTRY_TRANSP_DST_WIDTH           16

#define OPENFLOW_ENTRY_TRANSP_DST_POS             0

#define OPENFLOW_ENTRY_TRANSP_SRC_WIDTH           16

#define OPENFLOW_ENTRY_TRANSP_SRC_POS             16

#define OPENFLOW_ENTRY_IP_PROTO_WIDTH             8

#define OPENFLOW_ENTRY_IP_PROTO_POS               32

#define OPENFLOW_ENTRY_IP_DST_WIDTH               32

#define OPENFLOW_ENTRY_IP_DST_POS                 40

#define OPENFLOW_ENTRY_IP_SRC_WIDTH               32

#define OPENFLOW_ENTRY_IP_SRC_POS                 72

#define OPENFLOW_ENTRY_ETH_TYPE_WIDTH             16

#define OPENFLOW_ENTRY_ETH_TYPE_POS               104

#define OPENFLOW_ENTRY_ETH_DST_WIDTH              48

#define OPENFLOW_ENTRY_ETH_DST_POS                120

#define OPENFLOW_ENTRY_ETH_SRC_WIDTH              48

#define OPENFLOW_ENTRY_ETH_SRC_POS                168

#define OPENFLOW_ENTRY_SRC_PORT_WIDTH             8

#define OPENFLOW_ENTRY_SRC_PORT_POS               216

#define OPENFLOW_ENTRY_VLAN_ID_WIDTH              16

#define OPENFLOW_ENTRY_VLAN_ID_POS                224

#define OPENFLOW_ENTRY_WIDTH                      240

// The actionfield is composed of a bitmask specifying actions to take and arguments.
#define OPENFLOW_ACTION_WIDTH                     320

// Ports to forward on
#define OPENFLOW_FORWARD_BITMASK_WIDTH            16

#define OPENFLOW_FORWARD_BITMASK_POS              0

#define OPENFLOW_NF2_ACTION_FLAG_WIDTH            16

#define OPENFLOW_NF2_ACTION_FLAG_POS              16

// Vlan ID to be replaced
#define OPENFLOW_SET_VLAN_VID_WIDTH               16

#define OPENFLOW_SET_VLAN_VID_POS                 32

// Vlan priority to be replaced
#define OPENFLOW_SET_VLAN_PCP_WIDTH               8

#define OPENFLOW_SET_VLAN_PCP_POS                 48

// Source MAC address to be replaced
#define OPENFLOW_SET_DL_SRC_WIDTH                 48

#define OPENFLOW_SET_DL_SRC_POS                   56

// Destination MAC address to be replaced
#define OPENFLOW_SET_DL_DST_WIDTH                 48

#define OPENFLOW_SET_DL_DST_POS                   104

// Source network address to be replaced
#define OPENFLOW_SET_NW_SRC_WIDTH                 32

#define OPENFLOW_SET_NW_SRC_POS                   152

// Destination network address to be replaced
#define OPENFLOW_SET_NW_DST_WIDTH                 32

#define OPENFLOW_SET_NW_DST_POS                   184

// Source transport port to be replaced
#define OPENFLOW_SET_TP_SRC_WIDTH                 16

#define OPENFLOW_SET_TP_SRC_POS                   216

// Destination transport port to be replaced
#define OPENFLOW_SET_TP_DST_WIDTH                 16

#define OPENFLOW_SET_TP_DST_POS                   232

// ===== File: projects/openflow_switch/include/exact_match.xml =====

#define OPENFLOW_EXACT_ENTRY_PKT_COUNTER_WIDTH    25

#define OPENFLOW_EXACT_ENTRY_PKT_COUNTER_POS      0

#define OPENFLOW_EXACT_ENTRY_LAST_SEEN_WIDTH      7

#define OPENFLOW_EXACT_ENTRY_LAST_SEEN_POS        25

#define OPENFLOW_EXACT_ENTRY_BYTE_COUNTER_WIDTH   32

#define OPENFLOW_EXACT_ENTRY_BYTE_COUNTER_POS     32

#define OPENFLOW_EXACT_ENTRY_HDR_BASE_POS         0x00000000

#define OPENFLOW_EXACT_ENTRY_COUNTERS_POS         0x00000008

#define OPENFLOW_EXACT_ENTRY_ACTION_BASE_POS      0x0000000a

// -------------------------------------
//   Modules
// -------------------------------------

// Module tags
#define CORE_BASE_ADDR                      0x0000000
#define DEV_ID_BASE_ADDR                    0x0400000
#define MDIO_BASE_ADDR                      0x0440000
#define DMA_BASE_ADDR                       0x0500000
#define MAC_GRP_0_BASE_ADDR                 0x0600000
#define MAC_GRP_1_BASE_ADDR                 0x0640000
#define MAC_GRP_2_BASE_ADDR                 0x0680000
#define MAC_GRP_3_BASE_ADDR                 0x06c0000
#define CPU_QUEUE_0_BASE_ADDR               0x0700000
#define CPU_QUEUE_1_BASE_ADDR               0x0740000
#define CPU_QUEUE_2_BASE_ADDR               0x0780000
#define CPU_QUEUE_3_BASE_ADDR               0x07c0000
#define SRAM_BASE_ADDR                      0x1000000
#define UDP_BASE_ADDR                       0x2000000
#define OPENFLOW_LOOKUP_BASE_ADDR           0x2000000
#define IN_ARB_BASE_ADDR                    0x2000100
#define VLAN_REMOVER_BASE_ADDR              0x2000200
#define OPL_PROCESSOR_BASE_ADDR             0x2000240
#define HEADER_PARSER_BASE_ADDR             0x2000280
#define MATCH_ARBITER_BASE_ADDR             0x20002c0
#define BRAM_OQ_BASE_ADDR                   0x2000300
#define WDT_BASE_ADDR                       0x2000400
#define EXACT_MATCH_BASE_ADDR               0x2000500
#define OPENFLOW_WILDCARD_LOOKUP_BASE_ADDR  0x2001000
#define DRAM_BASE_ADDR                      0x4000000

#define CPU_QUEUE_OFFSET                  0x0040000
#define MAC_GRP_OFFSET                    0x0040000

/* ========== Registers ========== */

// Name: device_id (DEV_ID)
// Description: Device identification
// File: lib/verilog/core/utils/xml/device_id_reg.xml
#define DEV_ID_MD5_0_REG        0x0400000
#define DEV_ID_MD5_1_REG        0x0400004
#define DEV_ID_MD5_2_REG        0x0400008
#define DEV_ID_MD5_3_REG        0x040000c
#define DEV_ID_DEVICE_ID_REG    0x0400010
#define DEV_ID_REVISION_REG     0x0400014
#define DEV_ID_CPCI_ID_REG      0x0400018
#define DEV_ID_DEV_STR_0_REG    0x040001c
#define DEV_ID_DEV_STR_1_REG    0x0400020
#define DEV_ID_DEV_STR_2_REG    0x0400024
#define DEV_ID_DEV_STR_3_REG    0x0400028
#define DEV_ID_DEV_STR_4_REG    0x040002c
#define DEV_ID_DEV_STR_5_REG    0x0400030
#define DEV_ID_DEV_STR_6_REG    0x0400034
#define DEV_ID_DEV_STR_7_REG    0x0400038
#define DEV_ID_DEV_STR_8_REG    0x040003c
#define DEV_ID_DEV_STR_9_REG    0x0400040
#define DEV_ID_DEV_STR_10_REG   0x0400044
#define DEV_ID_DEV_STR_11_REG   0x0400048
#define DEV_ID_DEV_STR_12_REG   0x040004c
#define DEV_ID_DEV_STR_13_REG   0x0400050
#define DEV_ID_DEV_STR_14_REG   0x0400054
#define DEV_ID_DEV_STR_15_REG   0x0400058
#define DEV_ID_DEV_STR_16_REG   0x040005c
#define DEV_ID_DEV_STR_17_REG   0x0400060
#define DEV_ID_DEV_STR_18_REG   0x0400064
#define DEV_ID_DEV_STR_19_REG   0x0400068
#define DEV_ID_DEV_STR_20_REG   0x040006c
#define DEV_ID_DEV_STR_21_REG   0x0400070
#define DEV_ID_DEV_STR_22_REG   0x0400074
#define DEV_ID_DEV_STR_23_REG   0x0400078
#define DEV_ID_DEV_STR_24_REG   0x040007c

// Name: mdio (MDIO)
// Description: MDIO interface
// File: lib/verilog/core/io/mdio/xml/mdio.xml
#define MDIO_PHY_0_CONTROL_REG                                  0x0440000
#define MDIO_PHY_0_STATUS_REG                                   0x0440004
#define MDIO_PHY_0_PHY_ID_0_REG                                 0x0440008
#define MDIO_PHY_0_PHY_ID_1_REG                                 0x044000c
#define MDIO_PHY_0_AUTONEGOTIATION_ADVERT_REG                   0x0440010
#define MDIO_PHY_0_AUTONEG_LINK_PARTNER_BASE_PAGE_ABILITY_REG   0x0440014
#define MDIO_PHY_0_AUTONEG_EXPANSION_REG                        0x0440018
#define MDIO_PHY_0_AUTONEG_NEXT_PAGE_TX_REG                     0x044001c
#define MDIO_PHY_0_AUTONEG_LINK_PARTNER_RCVD_NEXT_PAGE_REG      0x0440020
#define MDIO_PHY_0_MASTER_SLAVE_CTRL_REG                        0x0440024
#define MDIO_PHY_0_MASTER_SLAVE_STATUS_REG                      0x0440028
#define MDIO_PHY_0_PSE_CTRL_REG                                 0x044002c
#define MDIO_PHY_0_PSE_STATUS_REG                               0x0440030
#define MDIO_PHY_0_MMD_ACCESS_CTRL_REG                          0x0440034
#define MDIO_PHY_0_MMD_ACCESS_STATUS_REG                        0x0440038
#define MDIO_PHY_0_EXTENDED_STATUS_REG                          0x044003c
#define MDIO_PHY_1_CONTROL_REG                                  0x0440080
#define MDIO_PHY_1_STATUS_REG                                   0x0440084
#define MDIO_PHY_1_PHY_ID_0_REG                                 0x0440088
#define MDIO_PHY_1_PHY_ID_1_REG                                 0x044008c
#define MDIO_PHY_1_AUTONEGOTIATION_ADVERT_REG                   0x0440090
#define MDIO_PHY_1_AUTONEG_LINK_PARTNER_BASE_PAGE_ABILITY_REG   0x0440094
#define MDIO_PHY_1_AUTONEG_EXPANSION_REG                        0x0440098
#define MDIO_PHY_1_AUTONEG_NEXT_PAGE_TX_REG                     0x044009c
#define MDIO_PHY_1_AUTONEG_LINK_PARTNER_RCVD_NEXT_PAGE_REG      0x04400a0
#define MDIO_PHY_1_MASTER_SLAVE_CTRL_REG                        0x04400a4
#define MDIO_PHY_1_MASTER_SLAVE_STATUS_REG                      0x04400a8
#define MDIO_PHY_1_PSE_CTRL_REG                                 0x04400ac
#define MDIO_PHY_1_PSE_STATUS_REG                               0x04400b0
#define MDIO_PHY_1_MMD_ACCESS_CTRL_REG                          0x04400b4
#define MDIO_PHY_1_MMD_ACCESS_STATUS_REG                        0x04400b8
#define MDIO_PHY_1_EXTENDED_STATUS_REG                          0x04400bc
#define MDIO_PHY_2_CONTROL_REG                                  0x0440100
#define MDIO_PHY_2_STATUS_REG                                   0x0440104
#define MDIO_PHY_2_PHY_ID_0_REG                                 0x0440108
#define MDIO_PHY_2_PHY_ID_1_REG                                 0x044010c
#define MDIO_PHY_2_AUTONEGOTIATION_ADVERT_REG                   0x0440110
#define MDIO_PHY_2_AUTONEG_LINK_PARTNER_BASE_PAGE_ABILITY_REG   0x0440114
#define MDIO_PHY_2_AUTONEG_EXPANSION_REG                        0x0440118
#define MDIO_PHY_2_AUTONEG_NEXT_PAGE_TX_REG                     0x044011c
#define MDIO_PHY_2_AUTONEG_LINK_PARTNER_RCVD_NEXT_PAGE_REG      0x0440120
#define MDIO_PHY_2_MASTER_SLAVE_CTRL_REG                        0x0440124
#define MDIO_PHY_2_MASTER_SLAVE_STATUS_REG                      0x0440128
#define MDIO_PHY_2_PSE_CTRL_REG                                 0x044012c
#define MDIO_PHY_2_PSE_STATUS_REG                               0x0440130
#define MDIO_PHY_2_MMD_ACCESS_CTRL_REG                          0x0440134
#define MDIO_PHY_2_MMD_ACCESS_STATUS_REG                        0x0440138
#define MDIO_PHY_2_EXTENDED_STATUS_REG                          0x044013c
#define MDIO_PHY_3_CONTROL_REG                                  0x0440180
#define MDIO_PHY_3_STATUS_REG                                   0x0440184
#define MDIO_PHY_3_PHY_ID_0_REG                                 0x0440188
#define MDIO_PHY_3_PHY_ID_1_REG                                 0x044018c
#define MDIO_PHY_3_AUTONEGOTIATION_ADVERT_REG                   0x0440190
#define MDIO_PHY_3_AUTONEG_LINK_PARTNER_BASE_PAGE_ABILITY_REG   0x0440194
#define MDIO_PHY_3_AUTONEG_EXPANSION_REG                        0x0440198
#define MDIO_PHY_3_AUTONEG_NEXT_PAGE_TX_REG                     0x044019c
#define MDIO_PHY_3_AUTONEG_LINK_PARTNER_RCVD_NEXT_PAGE_REG      0x04401a0
#define MDIO_PHY_3_MASTER_SLAVE_CTRL_REG                        0x04401a4
#define MDIO_PHY_3_MASTER_SLAVE_STATUS_REG                      0x04401a8
#define MDIO_PHY_3_PSE_CTRL_REG                                 0x04401ac
#define MDIO_PHY_3_PSE_STATUS_REG                               0x04401b0
#define MDIO_PHY_3_MMD_ACCESS_CTRL_REG                          0x04401b4
#define MDIO_PHY_3_MMD_ACCESS_STATUS_REG                        0x04401b8
#define MDIO_PHY_3_EXTENDED_STATUS_REG                          0x04401bc

#define MDIO_PHY_GROUP_BASE_ADDR   0x0440000
#define MDIO_PHY_GROUP_INST_OFFSET 0x0000080

// Name: dma (DMA)
// Description: DMA transfer module
// File: lib/verilog/core/dma/xml/dma.xml

// Name: nf2_mac_grp (MAC_GRP_0)
// Description: Ethernet MAC group
// File: lib/verilog/core/io_queues/ethernet_mac/xml/ethernet_mac.xml
#define MAC_GRP_0_CONTROL_REG                          0x0600000
#define MAC_GRP_0_RX_QUEUE_NUM_PKTS_IN_QUEUE_REG       0x0600004
#define MAC_GRP_0_RX_QUEUE_NUM_PKTS_STORED_REG         0x0600008
#define MAC_GRP_0_RX_QUEUE_NUM_PKTS_DROPPED_FULL_REG   0x060000c
#define MAC_GRP_0_RX_QUEUE_NUM_PKTS_DROPPED_BAD_REG    0x0600010
#define MAC_GRP_0_RX_QUEUE_NUM_PKTS_DEQUEUED_REG       0x0600014
#define MAC_GRP_0_RX_QUEUE_NUM_WORDS_PUSHED_REG        0x0600018
#define MAC_GRP_0_RX_QUEUE_NUM_BYTES_PUSHED_REG        0x060001c
#define MAC_GRP_0_TX_QUEUE_NUM_PKTS_IN_QUEUE_REG       0x0600020
#define MAC_GRP_0_TX_QUEUE_NUM_PKTS_ENQUEUED_REG       0x0600024
#define MAC_GRP_0_TX_QUEUE_NUM_PKTS_SENT_REG           0x0600028
#define MAC_GRP_0_TX_QUEUE_NUM_WORDS_PUSHED_REG        0x060002c
#define MAC_GRP_0_TX_QUEUE_NUM_BYTES_PUSHED_REG        0x0600030

// Name: nf2_mac_grp (MAC_GRP_1)
// Description: Ethernet MAC group
// File: lib/verilog/core/io_queues/ethernet_mac/xml/ethernet_mac.xml
#define MAC_GRP_1_CONTROL_REG                          0x0640000
#define MAC_GRP_1_RX_QUEUE_NUM_PKTS_IN_QUEUE_REG       0x0640004
#define MAC_GRP_1_RX_QUEUE_NUM_PKTS_STORED_REG         0x0640008
#define MAC_GRP_1_RX_QUEUE_NUM_PKTS_DROPPED_FULL_REG   0x064000c
#define MAC_GRP_1_RX_QUEUE_NUM_PKTS_DROPPED_BAD_REG    0x0640010
#define MAC_GRP_1_RX_QUEUE_NUM_PKTS_DEQUEUED_REG       0x0640014
#define MAC_GRP_1_RX_QUEUE_NUM_WORDS_PUSHED_REG        0x0640018
#define MAC_GRP_1_RX_QUEUE_NUM_BYTES_PUSHED_REG        0x064001c
#define MAC_GRP_1_TX_QUEUE_NUM_PKTS_IN_QUEUE_REG       0x0640020
#define MAC_GRP_1_TX_QUEUE_NUM_PKTS_ENQUEUED_REG       0x0640024
#define MAC_GRP_1_TX_QUEUE_NUM_PKTS_SENT_REG           0x0640028
#define MAC_GRP_1_TX_QUEUE_NUM_WORDS_PUSHED_REG        0x064002c
#define MAC_GRP_1_TX_QUEUE_NUM_BYTES_PUSHED_REG        0x0640030

// Name: nf2_mac_grp (MAC_GRP_2)
// Description: Ethernet MAC group
// File: lib/verilog/core/io_queues/ethernet_mac/xml/ethernet_mac.xml
#define MAC_GRP_2_CONTROL_REG                          0x0680000
#define MAC_GRP_2_RX_QUEUE_NUM_PKTS_IN_QUEUE_REG       0x0680004
#define MAC_GRP_2_RX_QUEUE_NUM_PKTS_STORED_REG         0x0680008
#define MAC_GRP_2_RX_QUEUE_NUM_PKTS_DROPPED_FULL_REG   0x068000c
#define MAC_GRP_2_RX_QUEUE_NUM_PKTS_DROPPED_BAD_REG    0x0680010
#define MAC_GRP_2_RX_QUEUE_NUM_PKTS_DEQUEUED_REG       0x0680014
#define MAC_GRP_2_RX_QUEUE_NUM_WORDS_PUSHED_REG        0x0680018
#define MAC_GRP_2_RX_QUEUE_NUM_BYTES_PUSHED_REG        0x068001c
#define MAC_GRP_2_TX_QUEUE_NUM_PKTS_IN_QUEUE_REG       0x0680020
#define MAC_GRP_2_TX_QUEUE_NUM_PKTS_ENQUEUED_REG       0x0680024
#define MAC_GRP_2_TX_QUEUE_NUM_PKTS_SENT_REG           0x0680028
#define MAC_GRP_2_TX_QUEUE_NUM_WORDS_PUSHED_REG        0x068002c
#define MAC_GRP_2_TX_QUEUE_NUM_BYTES_PUSHED_REG        0x0680030

// Name: nf2_mac_grp (MAC_GRP_3)
// Description: Ethernet MAC group
// File: lib/verilog/core/io_queues/ethernet_mac/xml/ethernet_mac.xml
#define MAC_GRP_3_CONTROL_REG                          0x06c0000
#define MAC_GRP_3_RX_QUEUE_NUM_PKTS_IN_QUEUE_REG       0x06c0004
#define MAC_GRP_3_RX_QUEUE_NUM_PKTS_STORED_REG         0x06c0008
#define MAC_GRP_3_RX_QUEUE_NUM_PKTS_DROPPED_FULL_REG   0x06c000c
#define MAC_GRP_3_RX_QUEUE_NUM_PKTS_DROPPED_BAD_REG    0x06c0010
#define MAC_GRP_3_RX_QUEUE_NUM_PKTS_DEQUEUED_REG       0x06c0014
#define MAC_GRP_3_RX_QUEUE_NUM_WORDS_PUSHED_REG        0x06c0018
#define MAC_GRP_3_RX_QUEUE_NUM_BYTES_PUSHED_REG        0x06c001c
#define MAC_GRP_3_TX_QUEUE_NUM_PKTS_IN_QUEUE_REG       0x06c0020
#define MAC_GRP_3_TX_QUEUE_NUM_PKTS_ENQUEUED_REG       0x06c0024
#define MAC_GRP_3_TX_QUEUE_NUM_PKTS_SENT_REG           0x06c0028
#define MAC_GRP_3_TX_QUEUE_NUM_WORDS_PUSHED_REG        0x06c002c
#define MAC_GRP_3_TX_QUEUE_NUM_BYTES_PUSHED_REG        0x06c0030

// Name: cpu_dma_queue (CPU_QUEUE_0)
// Description: CPU DMA queue
// File: lib/verilog/core/io_queues/cpu_dma_queue/xml/cpu_dma_queue.xml

// Name: cpu_dma_queue (CPU_QUEUE_1)
// Description: CPU DMA queue
// File: lib/verilog/core/io_queues/cpu_dma_queue/xml/cpu_dma_queue.xml

// Name: cpu_dma_queue (CPU_QUEUE_2)
// Description: CPU DMA queue
// File: lib/verilog/core/io_queues/cpu_dma_queue/xml/cpu_dma_queue.xml

// Name: cpu_dma_queue (CPU_QUEUE_3)
// Description: CPU DMA queue
// File: lib/verilog/core/io_queues/cpu_dma_queue/xml/cpu_dma_queue.xml

// Name: SRAM (SRAM)
// Description: SRAM

// Name: openflow_output_port_lookup (OPENFLOW_LOOKUP)
// Description: Output Port Lookup for OpenFlow hardware datapath
// File: projects/openflow_switch/include/output_port_lookup.xml
#define OPENFLOW_LOOKUP_WILDCARD_MISSES_REG      0x2000000
#define OPENFLOW_LOOKUP_WILDCARD_HITS_REG        0x2000004
#define OPENFLOW_LOOKUP_EXACT_MISSES_REG         0x2000008
#define OPENFLOW_LOOKUP_EXACT_HITS_REG           0x200000c
#define OPENFLOW_LOOKUP_NUM_PKTS_DROPPED_0_REG   0x2000010
#define OPENFLOW_LOOKUP_NUM_PKTS_DROPPED_1_REG   0x2000014
#define OPENFLOW_LOOKUP_NUM_PKTS_DROPPED_2_REG   0x2000018
#define OPENFLOW_LOOKUP_NUM_PKTS_DROPPED_3_REG   0x200001c
#define OPENFLOW_LOOKUP_NUM_PKTS_DROPPED_4_REG   0x2000020
#define OPENFLOW_LOOKUP_NUM_PKTS_DROPPED_5_REG   0x2000024
#define OPENFLOW_LOOKUP_NUM_PKTS_DROPPED_6_REG   0x2000028
#define OPENFLOW_LOOKUP_NUM_PKTS_DROPPED_7_REG   0x200002c
#define OPENFLOW_LOOKUP_DUMY_SOFTWARE_0_REG      0x2000030
#define OPENFLOW_LOOKUP_DUMY_SOFTWARE_1_REG      0x2000034
#define OPENFLOW_LOOKUP_TIMER_REG                0x2000038

// Name: in_arb (IN_ARB)
// Description: Round-robin input arbiter
// File: lib/verilog/core/input_arbiter/rr_input_arbiter/xml/rr_input_arbiter.xml
#define IN_ARB_NUM_PKTS_SENT_REG        0x2000100
#define IN_ARB_LAST_PKT_WORD_0_HI_REG   0x2000104
#define IN_ARB_LAST_PKT_WORD_0_LO_REG   0x2000108
#define IN_ARB_LAST_PKT_CTRL_0_REG      0x200010c
#define IN_ARB_LAST_PKT_WORD_1_HI_REG   0x2000110
#define IN_ARB_LAST_PKT_WORD_1_LO_REG   0x2000114
#define IN_ARB_LAST_PKT_CTRL_1_REG      0x2000118
#define IN_ARB_STATE_REG                0x200011c

// Name: vlan_remover (VLAN_REMOVER)
// Description: Remove vlan tag and ethtype if ethtype is vlan, and store them into module header
// File: projects/openflow_switch/include/vlan_remover.xml

// Name: opl_processor (OPL_PROCESSOR)
// Description: opl_processor
// File: projects/openflow_switch/include/opl_processor.xml

// Name: header_parser (HEADER_PARSER)
// Description: Chop ether/IP/UDP-TCP header into 11 tuples
// File: projects/openflow_switch/include/header_parser.xml

// Name: match_arbiter (MATCH_ARBITER)
// Description: Arbitration between exact and wildcard lookups results
// File: projects/openflow_switch/include/match_arbiter.xml

// Name: bram_output_queues (BRAM_OQ)
// Description: BRAM-based output queues
// File: lib/verilog/core/output_queues/bram_output_queues/xml/bram_output_queues.xml
#define BRAM_OQ_DISABLE_QUEUES_REG                   0x2000300
#define BRAM_OQ_QUEUE_0_NUM_PKT_BYTES_RECEIVED_REG   0x2000380
#define BRAM_OQ_QUEUE_0_NUM_PKTS_RECEIVED_REG        0x2000384
#define BRAM_OQ_QUEUE_0_NUM_PKTS_DROPPED_REG         0x2000388
#define BRAM_OQ_QUEUE_0_NUM_WORDS_IN_QUEUE_REG       0x200038c
#define BRAM_OQ_QUEUE_1_NUM_PKT_BYTES_RECEIVED_REG   0x2000390
#define BRAM_OQ_QUEUE_1_NUM_PKTS_RECEIVED_REG        0x2000394
#define BRAM_OQ_QUEUE_1_NUM_PKTS_DROPPED_REG         0x2000398
#define BRAM_OQ_QUEUE_1_NUM_WORDS_IN_QUEUE_REG       0x200039c
#define BRAM_OQ_QUEUE_2_NUM_PKT_BYTES_RECEIVED_REG   0x20003a0
#define BRAM_OQ_QUEUE_2_NUM_PKTS_RECEIVED_REG        0x20003a4
#define BRAM_OQ_QUEUE_2_NUM_PKTS_DROPPED_REG         0x20003a8
#define BRAM_OQ_QUEUE_2_NUM_WORDS_IN_QUEUE_REG       0x20003ac
#define BRAM_OQ_QUEUE_3_NUM_PKT_BYTES_RECEIVED_REG   0x20003b0
#define BRAM_OQ_QUEUE_3_NUM_PKTS_RECEIVED_REG        0x20003b4
#define BRAM_OQ_QUEUE_3_NUM_PKTS_DROPPED_REG         0x20003b8
#define BRAM_OQ_QUEUE_3_NUM_WORDS_IN_QUEUE_REG       0x20003bc
#define BRAM_OQ_QUEUE_4_NUM_PKT_BYTES_RECEIVED_REG   0x20003c0
#define BRAM_OQ_QUEUE_4_NUM_PKTS_RECEIVED_REG        0x20003c4
#define BRAM_OQ_QUEUE_4_NUM_PKTS_DROPPED_REG         0x20003c8
#define BRAM_OQ_QUEUE_4_NUM_WORDS_IN_QUEUE_REG       0x20003cc
#define BRAM_OQ_QUEUE_5_NUM_PKT_BYTES_RECEIVED_REG   0x20003d0
#define BRAM_OQ_QUEUE_5_NUM_PKTS_RECEIVED_REG        0x20003d4
#define BRAM_OQ_QUEUE_5_NUM_PKTS_DROPPED_REG         0x20003d8
#define BRAM_OQ_QUEUE_5_NUM_WORDS_IN_QUEUE_REG       0x20003dc
#define BRAM_OQ_QUEUE_6_NUM_PKT_BYTES_RECEIVED_REG   0x20003e0
#define BRAM_OQ_QUEUE_6_NUM_PKTS_RECEIVED_REG        0x20003e4
#define BRAM_OQ_QUEUE_6_NUM_PKTS_DROPPED_REG         0x20003e8
#define BRAM_OQ_QUEUE_6_NUM_WORDS_IN_QUEUE_REG       0x20003ec
#define BRAM_OQ_QUEUE_7_NUM_PKT_BYTES_RECEIVED_REG   0x20003f0
#define BRAM_OQ_QUEUE_7_NUM_PKTS_RECEIVED_REG        0x20003f4
#define BRAM_OQ_QUEUE_7_NUM_PKTS_DROPPED_REG         0x20003f8
#define BRAM_OQ_QUEUE_7_NUM_WORDS_IN_QUEUE_REG       0x20003fc

#define BRAM_OQ_QUEUE_GROUP_BASE_ADDR   0x2000380
#define BRAM_OQ_QUEUE_GROUP_INST_OFFSET 0x0000010

// Name: watchdog (WDT)
// Description: Watchdog timer
// File: projects/openflow_switch/include/watchdog.xml
#define WDT_ENABLE_FLG_REG   0x2000400
#define WDT_COUNTER_REG      0x2000404

// Name: exact_match (EXACT_MATCH)
// Description: exact match lookup
// File: projects/openflow_switch/include/exact_match.xml

// Name: wildcard_match (OPENFLOW_WILDCARD_LOOKUP)
// Description: wildcard match lookup
// File: projects/openflow_switch/include/wildcard_match.xml
#define OPENFLOW_WILDCARD_LOOKUP_ACTION_0_REG          0x2001000
#define OPENFLOW_WILDCARD_LOOKUP_ACTION_1_REG          0x2001004
#define OPENFLOW_WILDCARD_LOOKUP_ACTION_2_REG          0x2001008
#define OPENFLOW_WILDCARD_LOOKUP_ACTION_3_REG          0x200100c
#define OPENFLOW_WILDCARD_LOOKUP_ACTION_4_REG          0x2001010
#define OPENFLOW_WILDCARD_LOOKUP_ACTION_5_REG          0x2001014
#define OPENFLOW_WILDCARD_LOOKUP_ACTION_6_REG          0x2001018
#define OPENFLOW_WILDCARD_LOOKUP_ACTION_7_REG          0x200101c
#define OPENFLOW_WILDCARD_LOOKUP_ACTION_8_REG          0x2001020
#define OPENFLOW_WILDCARD_LOOKUP_ACTION_9_REG          0x2001024
#define OPENFLOW_WILDCARD_LOOKUP_CMP_MASK_0_REG        0x2001028
#define OPENFLOW_WILDCARD_LOOKUP_CMP_MASK_1_REG        0x200102c
#define OPENFLOW_WILDCARD_LOOKUP_CMP_MASK_2_REG        0x2001030
#define OPENFLOW_WILDCARD_LOOKUP_CMP_MASK_3_REG        0x2001034
#define OPENFLOW_WILDCARD_LOOKUP_CMP_MASK_4_REG        0x2001038
#define OPENFLOW_WILDCARD_LOOKUP_CMP_MASK_5_REG        0x200103c
#define OPENFLOW_WILDCARD_LOOKUP_CMP_MASK_6_REG        0x2001040
#define OPENFLOW_WILDCARD_LOOKUP_CMP_MASK_7_REG        0x2001044
#define OPENFLOW_WILDCARD_LOOKUP_CMP_0_REG             0x2001048
#define OPENFLOW_WILDCARD_LOOKUP_CMP_1_REG             0x200104c
#define OPENFLOW_WILDCARD_LOOKUP_CMP_2_REG             0x2001050
#define OPENFLOW_WILDCARD_LOOKUP_CMP_3_REG             0x2001054
#define OPENFLOW_WILDCARD_LOOKUP_CMP_4_REG             0x2001058
#define OPENFLOW_WILDCARD_LOOKUP_CMP_5_REG             0x200105c
#define OPENFLOW_WILDCARD_LOOKUP_CMP_6_REG             0x2001060
#define OPENFLOW_WILDCARD_LOOKUP_CMP_7_REG             0x2001064
#define OPENFLOW_WILDCARD_LOOKUP_READ_ADDR_REG         0x2001068
#define OPENFLOW_WILDCARD_LOOKUP_WRITE_ADDR_REG        0x200106c
#define OPENFLOW_WILDCARD_LOOKUP_BYTES_HIT_0_REG       0x2001070
#define OPENFLOW_WILDCARD_LOOKUP_BYTES_HIT_1_REG       0x2001074
#define OPENFLOW_WILDCARD_LOOKUP_BYTES_HIT_2_REG       0x2001078
#define OPENFLOW_WILDCARD_LOOKUP_BYTES_HIT_3_REG       0x200107c
#define OPENFLOW_WILDCARD_LOOKUP_BYTES_HIT_4_REG       0x2001080
#define OPENFLOW_WILDCARD_LOOKUP_BYTES_HIT_5_REG       0x2001084
#define OPENFLOW_WILDCARD_LOOKUP_BYTES_HIT_6_REG       0x2001088
#define OPENFLOW_WILDCARD_LOOKUP_BYTES_HIT_7_REG       0x200108c
#define OPENFLOW_WILDCARD_LOOKUP_BYTES_HIT_8_REG       0x2001090
#define OPENFLOW_WILDCARD_LOOKUP_BYTES_HIT_9_REG       0x2001094
#define OPENFLOW_WILDCARD_LOOKUP_BYTES_HIT_10_REG      0x2001098
#define OPENFLOW_WILDCARD_LOOKUP_BYTES_HIT_11_REG      0x200109c
#define OPENFLOW_WILDCARD_LOOKUP_BYTES_HIT_12_REG      0x20010a0
#define OPENFLOW_WILDCARD_LOOKUP_BYTES_HIT_13_REG      0x20010a4
#define OPENFLOW_WILDCARD_LOOKUP_BYTES_HIT_14_REG      0x20010a8
#define OPENFLOW_WILDCARD_LOOKUP_BYTES_HIT_15_REG      0x20010ac
#define OPENFLOW_WILDCARD_LOOKUP_BYTES_HIT_16_REG      0x20010b0
#define OPENFLOW_WILDCARD_LOOKUP_BYTES_HIT_17_REG      0x20010b4
#define OPENFLOW_WILDCARD_LOOKUP_BYTES_HIT_18_REG      0x20010b8
#define OPENFLOW_WILDCARD_LOOKUP_BYTES_HIT_19_REG      0x20010bc
#define OPENFLOW_WILDCARD_LOOKUP_BYTES_HIT_20_REG      0x20010c0
#define OPENFLOW_WILDCARD_LOOKUP_BYTES_HIT_21_REG      0x20010c4
#define OPENFLOW_WILDCARD_LOOKUP_BYTES_HIT_22_REG      0x20010c8
#define OPENFLOW_WILDCARD_LOOKUP_BYTES_HIT_23_REG      0x20010cc
#define OPENFLOW_WILDCARD_LOOKUP_BYTES_HIT_24_REG      0x20010d0
#define OPENFLOW_WILDCARD_LOOKUP_BYTES_HIT_25_REG      0x20010d4
#define OPENFLOW_WILDCARD_LOOKUP_BYTES_HIT_26_REG      0x20010d8
#define OPENFLOW_WILDCARD_LOOKUP_BYTES_HIT_27_REG      0x20010dc
#define OPENFLOW_WILDCARD_LOOKUP_BYTES_HIT_28_REG      0x20010e0
#define OPENFLOW_WILDCARD_LOOKUP_BYTES_HIT_29_REG      0x20010e4
#define OPENFLOW_WILDCARD_LOOKUP_BYTES_HIT_30_REG      0x20010e8
#define OPENFLOW_WILDCARD_LOOKUP_BYTES_HIT_31_REG      0x20010ec
#define OPENFLOW_WILDCARD_LOOKUP_PKTS_HIT_0_REG        0x20010f0
#define OPENFLOW_WILDCARD_LOOKUP_PKTS_HIT_1_REG        0x20010f4
#define OPENFLOW_WILDCARD_LOOKUP_PKTS_HIT_2_REG        0x20010f8
#define OPENFLOW_WILDCARD_LOOKUP_PKTS_HIT_3_REG        0x20010fc
#define OPENFLOW_WILDCARD_LOOKUP_PKTS_HIT_4_REG        0x2001100
#define OPENFLOW_WILDCARD_LOOKUP_PKTS_HIT_5_REG        0x2001104
#define OPENFLOW_WILDCARD_LOOKUP_PKTS_HIT_6_REG        0x2001108
#define OPENFLOW_WILDCARD_LOOKUP_PKTS_HIT_7_REG        0x200110c
#define OPENFLOW_WILDCARD_LOOKUP_PKTS_HIT_8_REG        0x2001110
#define OPENFLOW_WILDCARD_LOOKUP_PKTS_HIT_9_REG        0x2001114
#define OPENFLOW_WILDCARD_LOOKUP_PKTS_HIT_10_REG       0x2001118
#define OPENFLOW_WILDCARD_LOOKUP_PKTS_HIT_11_REG       0x200111c
#define OPENFLOW_WILDCARD_LOOKUP_PKTS_HIT_12_REG       0x2001120
#define OPENFLOW_WILDCARD_LOOKUP_PKTS_HIT_13_REG       0x2001124
#define OPENFLOW_WILDCARD_LOOKUP_PKTS_HIT_14_REG       0x2001128
#define OPENFLOW_WILDCARD_LOOKUP_PKTS_HIT_15_REG       0x200112c
#define OPENFLOW_WILDCARD_LOOKUP_PKTS_HIT_16_REG       0x2001130
#define OPENFLOW_WILDCARD_LOOKUP_PKTS_HIT_17_REG       0x2001134
#define OPENFLOW_WILDCARD_LOOKUP_PKTS_HIT_18_REG       0x2001138
#define OPENFLOW_WILDCARD_LOOKUP_PKTS_HIT_19_REG       0x200113c
#define OPENFLOW_WILDCARD_LOOKUP_PKTS_HIT_20_REG       0x2001140
#define OPENFLOW_WILDCARD_LOOKUP_PKTS_HIT_21_REG       0x2001144
#define OPENFLOW_WILDCARD_LOOKUP_PKTS_HIT_22_REG       0x2001148
#define OPENFLOW_WILDCARD_LOOKUP_PKTS_HIT_23_REG       0x200114c
#define OPENFLOW_WILDCARD_LOOKUP_PKTS_HIT_24_REG       0x2001150
#define OPENFLOW_WILDCARD_LOOKUP_PKTS_HIT_25_REG       0x2001154
#define OPENFLOW_WILDCARD_LOOKUP_PKTS_HIT_26_REG       0x2001158
#define OPENFLOW_WILDCARD_LOOKUP_PKTS_HIT_27_REG       0x200115c
#define OPENFLOW_WILDCARD_LOOKUP_PKTS_HIT_28_REG       0x2001160
#define OPENFLOW_WILDCARD_LOOKUP_PKTS_HIT_29_REG       0x2001164
#define OPENFLOW_WILDCARD_LOOKUP_PKTS_HIT_30_REG       0x2001168
#define OPENFLOW_WILDCARD_LOOKUP_PKTS_HIT_31_REG       0x200116c
#define OPENFLOW_WILDCARD_LOOKUP_DUMMY_1_REG           0x2001170
#define OPENFLOW_WILDCARD_LOOKUP_DUMMY_2_REG           0x2001174
#define OPENFLOW_WILDCARD_LOOKUP_LAST_SEEN_TS_0_REG    0x2001178
#define OPENFLOW_WILDCARD_LOOKUP_LAST_SEEN_TS_1_REG    0x200117c
#define OPENFLOW_WILDCARD_LOOKUP_LAST_SEEN_TS_2_REG    0x2001180
#define OPENFLOW_WILDCARD_LOOKUP_LAST_SEEN_TS_3_REG    0x2001184
#define OPENFLOW_WILDCARD_LOOKUP_LAST_SEEN_TS_4_REG    0x2001188
#define OPENFLOW_WILDCARD_LOOKUP_LAST_SEEN_TS_5_REG    0x200118c
#define OPENFLOW_WILDCARD_LOOKUP_LAST_SEEN_TS_6_REG    0x2001190
#define OPENFLOW_WILDCARD_LOOKUP_LAST_SEEN_TS_7_REG    0x2001194
#define OPENFLOW_WILDCARD_LOOKUP_LAST_SEEN_TS_8_REG    0x2001198
#define OPENFLOW_WILDCARD_LOOKUP_LAST_SEEN_TS_9_REG    0x200119c
#define OPENFLOW_WILDCARD_LOOKUP_LAST_SEEN_TS_10_REG   0x20011a0
#define OPENFLOW_WILDCARD_LOOKUP_LAST_SEEN_TS_11_REG   0x20011a4
#define OPENFLOW_WILDCARD_LOOKUP_LAST_SEEN_TS_12_REG   0x20011a8
#define OPENFLOW_WILDCARD_LOOKUP_LAST_SEEN_TS_13_REG   0x20011ac
#define OPENFLOW_WILDCARD_LOOKUP_LAST_SEEN_TS_14_REG   0x20011b0
#define OPENFLOW_WILDCARD_LOOKUP_LAST_SEEN_TS_15_REG   0x20011b4
#define OPENFLOW_WILDCARD_LOOKUP_LAST_SEEN_TS_16_REG   0x20011b8
#define OPENFLOW_WILDCARD_LOOKUP_LAST_SEEN_TS_17_REG   0x20011bc
#define OPENFLOW_WILDCARD_LOOKUP_LAST_SEEN_TS_18_REG   0x20011c0
#define OPENFLOW_WILDCARD_LOOKUP_LAST_SEEN_TS_19_REG   0x20011c4
#define OPENFLOW_WILDCARD_LOOKUP_LAST_SEEN_TS_20_REG   0x20011c8
#define OPENFLOW_WILDCARD_LOOKUP_LAST_SEEN_TS_21_REG   0x20011cc
#define OPENFLOW_WILDCARD_LOOKUP_LAST_SEEN_TS_22_REG   0x20011d0
#define OPENFLOW_WILDCARD_LOOKUP_LAST_SEEN_TS_23_REG   0x20011d4
#define OPENFLOW_WILDCARD_LOOKUP_LAST_SEEN_TS_24_REG   0x20011d8
#define OPENFLOW_WILDCARD_LOOKUP_LAST_SEEN_TS_25_REG   0x20011dc
#define OPENFLOW_WILDCARD_LOOKUP_LAST_SEEN_TS_26_REG   0x20011e0
#define OPENFLOW_WILDCARD_LOOKUP_LAST_SEEN_TS_27_REG   0x20011e4
#define OPENFLOW_WILDCARD_LOOKUP_LAST_SEEN_TS_28_REG   0x20011e8
#define OPENFLOW_WILDCARD_LOOKUP_LAST_SEEN_TS_29_REG   0x20011ec
#define OPENFLOW_WILDCARD_LOOKUP_LAST_SEEN_TS_30_REG   0x20011f0
#define OPENFLOW_WILDCARD_LOOKUP_LAST_SEEN_TS_31_REG   0x20011f4

// Name: DRAM (DRAM)
// Description: DRAM

#endif
