#!/usr/bin/perl -w
# test_flow_expired

use strict;
use OF::Includes;

sub my_test {

	my ($sock) = @_;
	
	my $max_idle = 0x1; # second before flow expiration

	# Set flags to make sure we get flow expiration messages
	enable_flow_expirations($ofp, $sock);

	my $hdr_args = {
		version => get_of_ver(),
		type    => $enums{'OFPT_FLOW_MOD'},
		length  => $ofp->sizeof('ofp_flow_mod') + $ofp->sizeof('ofp_action'),
		xid     => 0x0000000
	};

	my $match_args = {
		wildcards => 0,
		in_port   => 1,
		dl_src    => [ 0, 0, 0, 0, 0, 2 ],
		dl_dst    => [ 0, 0, 0, 0, 0, 1 ],
		dl_vlan   => 0xffff,
		dl_type   => 0x800,
		nw_src    => 0xc0a80128,             #192.168.1.40
		nw_dst    => 0xc0a80028,             #192.168.0.40
		nw_proto  => 0xff,                   #tcp
		tp_src    => 0,
		tp_dst    => 0
	};

	my $action_output_args = {
		max_len => 0,                        # send entire packet
		port    => 0
	};

	my $action_args = {
		type => $enums{'OFPAT_OUTPUT'},
		arg  => { output => $action_output_args }
	};
	my $action = $ofp->pack( 'ofp_action', $action_args );

	# not sure why either two actions are being sent or structure packing is off.
	my $flow_mod_args = {
		header    => $hdr_args,
		match     => $match_args,
		command   => $enums{'OFPFC_ADD'},
		max_idle  => $max_idle,
		buffer_id => 0x0102,
		priority  => 0,
		reserved  => 0
	};
	my $flow_mod = $ofp->pack( 'ofp_flow_mod', $flow_mod_args );

	my $pkt = $flow_mod . $action;

	#print HexDump($pkt);

	# Send 'flow_mod' message
	print $sock $pkt;
	print "sent second message\n";

	my $pkt_len   = 0;
	my $pkt_total = 0;
	wait_for_flow_expired( $ofp, $sock, $pkt_len, $pkt_total );

}

run_black_box_test( \&my_test );

