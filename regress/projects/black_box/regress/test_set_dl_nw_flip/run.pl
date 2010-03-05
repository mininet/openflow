#!/usr/bin/perl -w
# test_set_nw_dst

use strict;
use OF::Includes;

sub send_expect_exact {
    my ($ofp, $sock, $options_ref, $in_port_offset, $out_port_offset, $max_idle, $pkt_len) = @_;

    my $in_port = $in_port_offset + $$options_ref{'port_base'};
    my $out_port = $out_port_offset + $$options_ref{'port_base'};

    # in_port refers to the flow mod entry's input

    # Create the payload ourselves to make sure the two packets match
    # Jean II
    my $pkt_payload = [map {int(rand(256))} (1..($pkt_len - 8 - 4 - 16 - 14))];

    # This is the packet we are sending... - Jean II
    my $test_pkt_args = {
	DA     => "00:00:00:00:00:" . sprintf( "%02d", $out_port ),
	SA     => "00:00:00:00:00:" . sprintf( "%02d", $in_port ),
	src_ip => "192.168.200." .     ( $in_port ),
	dst_ip => "192.168.201." .     ( $out_port ),
	tos => 0x0,
	ttl => 64,
	len => $pkt_len,
	src_port => 1,
	dst_port => 0,
	data => $pkt_payload
    };
    my $test_pkt = new NF2::UDP_pkt(%$test_pkt_args);

    # This is the packet we are expecting to receive - Jean II
    my $expect_pkt_args = {
	DA     => "00:00:00:00:00:" . sprintf( "%02d", $in_port ),
	SA     => "00:00:00:00:00:" . sprintf( "%02d", $out_port ),
	src_ip => "192.168.201." .     ( $out_port ),
	dst_ip => "192.168.200." .     ( $in_port ),
	tos => 0x0,
	ttl => 64,
	len => $pkt_len,
	src_port => 1,
	dst_port => 0,
	data => $pkt_payload
    };
    my $expect_pkt = new NF2::UDP_pkt(%$expect_pkt_args);

    #print HexDump ($test_pkt->packed);

    my $wildcards = 0x0;		       # exact match
    my $flags = $enums{'OFPFF_SEND_FLOW_REM'}; # want flow expiry

    # Get the various addresses in the expected packet - Jean II
    my $chg_val_dl_da = ${$expect_pkt->{Ethernet_hdr}}->DA;
    my $chg_val_dl_sa = ${$expect_pkt->{Ethernet_hdr}}->SA;
    my $chg_val_nw_dst = ${$expect_pkt->{IP_hdr}}->dst_ip;
    my $chg_val_nw_src = ${$expect_pkt->{IP_hdr}}->src_ip;
    my @dl_da_addr_chg = NF2::PDU::get_MAC_address($chg_val_dl_da);
    my @dl_sa_addr_chg = NF2::PDU::get_MAC_address($chg_val_dl_sa);
    my $nw_dst_addr_chg;
    my $ok_org;
    ($nw_dst_addr_chg, $ok_org) = NF2::IP_hdr::getIP($chg_val_nw_dst);
    my $nw_src_addr_chg;
    ($nw_src_addr_chg, $ok_org) = NF2::IP_hdr::getIP($chg_val_nw_src);

    # Create the desired rewrite actions
    my @pad_6 = (0,0,0,0,0,0);
    my $action_mod_dl_da_args = {
	type => $enums{'OFPAT_SET_DL_DST'},
	len  => $ofp->sizeof('ofp_action_dl_addr'),
	dl_addr => \@dl_da_addr_chg,
	pad  => \@pad_6,
    };
    my $action_mod_dl_da = $ofp->pack('ofp_action_dl_addr', $action_mod_dl_da_args);
    my $action_mod_dl_sa_args = {
	type => $enums{'OFPAT_SET_DL_SRC'},
	len  => $ofp->sizeof('ofp_action_dl_addr'),
	dl_addr => \@dl_sa_addr_chg,
	pad  => \@pad_6,
    };
    my $action_mod_dl_sa = $ofp->pack('ofp_action_dl_addr', $action_mod_dl_sa_args);
    my $action_mod_nw_dst_args = {
	type => $enums{'OFPAT_SET_NW_DST'},
	len => $ofp->sizeof('ofp_action_nw_addr'),
	nw_addr => $nw_dst_addr_chg,
    };
    my $action_mod_nw_dst = $ofp->pack( 'ofp_action_nw_addr', $action_mod_nw_dst_args );
    my $action_mod_nw_src_args = {
	type => $enums{'OFPAT_SET_NW_SRC'},
	len => $ofp->sizeof('ofp_action_nw_addr'),
	nw_addr => $nw_src_addr_chg,
    };
    my $action_mod_nw_src = $ofp->pack( 'ofp_action_nw_addr', $action_mod_nw_src_args );

    # Output action to get the packet out someplace - Jean II
    my $action_output_args = {
	type => $enums{'OFPAT_OUTPUT'},
	len => $ofp->sizeof('ofp_action_output'),
	port => $out_port,
	max_len => 0,                                     # send entire packet
    };
    my $action_output = $ofp->pack( 'ofp_action_output', $action_output_args );

    # Aggregate all actions together
    my $action_bytes = $action_mod_dl_da . $action_mod_dl_sa . $action_mod_nw_dst . $action_mod_nw_src . $action_output;

    my $flow_mod_pkt =
	  create_flow_mod_from_udp_actionbytes( $ofp, $test_pkt, $in_port, $max_idle, $flags, $wildcards, 'OFPFC_ADD', $action_bytes);

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

sub test_set_nw_dst {
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
    for_all_port_pairs($ofp, $sock, $options_ref, \&test_set_nw_dst, 0x0);
}

run_black_box_test(\&my_test, \@ARGV);
