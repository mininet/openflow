#!/usr/bin/perl -w
# test_set_nw_tos

use strict;
use OF::Includes;

# Please check the following :
# http://en.wikipedia.org/wiki/Type_of_Service

sub send_expect_exact {
    my ($ofp, $sock, $options_ref, $in_port_offset, $out_port_offset, $max_idle, $pkt_len, $vlan_id) = @_;

    my $in_port = $in_port_offset + $$options_ref{'port_base'};
    my $out_port = $out_port_offset + $$options_ref{'port_base'};

    # in_port refers to the flow mod entry's input

    # Create the payload ourselves to make sure the two packets match
    # Jean II
    my $pkt_payload = [map {int(rand(256))} (1..($pkt_len - 8 - 4 - 16 - 14))];

    # This is the packet we are sending... - Jean II
    # Set an ECN bit to see if it gets clobbered
    my $test_nw_tos = 0xA8;
    my $test_pkt_args = {
	DA     => "00:00:00:00:00:" . sprintf( "%02d", $out_port ),
	SA     => "00:00:00:00:00:" . sprintf( "%02d", $in_port ),
	src_ip => "192.168.200." . ( $in_port ),
	dst_ip => "192.168.201." . ( $out_port ),
	tos => $test_nw_tos | 0x01, # => 0xA9
	ttl => 64,
	len => $pkt_len,
	src_port => 1,
	dst_port => 0,
	data => $pkt_payload
    };
    my $test_pkt = new NF2::UDP_pkt(%$test_pkt_args);

    # This is the packet we are expecting to receive - Jean II
    my $expect_pkt_args = {
	DA     => "00:00:00:00:00:" . sprintf( "%02d", $out_port ),
	SA     => "00:00:00:00:00:" . sprintf( "%02d", $in_port ),
	src_ip => "192.168.200." . ( $in_port ),
	dst_ip => "192.168.201." . ( $out_port ),
	tos => 0x54 | 0x01,	# 0x55
	ttl => 64,
	len => $pkt_len,
	src_port => 1,
	dst_port => 0,
	data => $pkt_payload
    };
    my $expect_pkt = new NF2::UDP_pkt(%$expect_pkt_args);

    #print HexDump ($test_pkt->packed);

    my $wildcards = 0x0;	# exact match
    my $flags = $enums{'OFPFF_SEND_FLOW_REM'}; # want flow expiry
    # Don't set ECN bits here, OVS reject it as invalid...
    my $nw_tos = 0x54;

    my $flow_mod_pkt = create_flow_mod_from_udp_action($ofp, $test_pkt, $in_port, $out_port, $max_idle, $flags, $wildcards, 'OFPFC_ADD', 'nw_tos', $nw_tos, $vlan_id, $test_nw_tos);

    #print HexDump($flow_mod_pkt);

    # Send 'flow_mod' message
    print $sock $flow_mod_pkt;
    print "sent flow_mod message\n";

    # Give OF switch time to process the flow mod
    usleep($$options_ref{'send_delay'});

    # Send a packet - ensure packet comes out desired port
    nftest_send("eth" . ($in_port_offset + 1), $test_pkt->packed);
    nftest_expect("eth" . ($out_port_offset + 1), $expect_pkt->packed);
}

sub test_set_nw_tos {
    my ($ofp, $sock, $options_ref, $i, $j, $wildcards) = @_;

    my $max_idle =  $$options_ref{'max_idle'};
    my $pkt_len = $$options_ref{'pkt_len'};
    my $pkt_total = $$options_ref{'pkt_total'};

    send_expect_exact($ofp, $sock, $options_ref, $i, $j, $max_idle, $pkt_len);
    wait_for_flow_expired($ofp, $sock, $options_ref, $pkt_len, $pkt_total);
}

sub my_test {
    my ($sock, $options_ref) = @_;

    # send from every port to every other port
    for_all_port_pairs( $ofp, $sock, $options_ref, \&test_set_nw_tos, 0x0);
}

run_black_box_test(\&my_test, \@ARGV);
