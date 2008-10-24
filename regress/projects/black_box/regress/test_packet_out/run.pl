#!/usr/bin/perl -w
# test_packet_out

use strict;
use OF::Includes;

sub my_test {

	my ( $sock, $options_ref ) = @_;

	my $port_base = $$options_ref{'port_base'};
	my $in_port   = $port_base;
	my $out_port  = $in_port + 1;

	my $pkt = get_default_black_box_pkt( $in_port, $out_port );

	my $hdr_args = {
		version => get_of_ver(),
		type    => $enums{'OFPT_PACKET_OUT'},
		length  => $ofp->sizeof('ofp_packet_out') +
		  $ofp->sizeof('ofp_action_output') +
		  length( $pkt->packed ),    # should generate automatically!
		xid => 0x0000abcd
	};
	my $packet_out_args = {
		header    => $hdr_args,
		buffer_id => -1,                    # data included in this packet
		in_port   => $enums{'OFPP_NONE'},
		actions_len => $ofp->sizeof('ofp_action_output')
	};
	my $packet_out = $ofp->pack( 'ofp_packet_out', $packet_out_args );
	my $action_output_args = {
		type    => $enums{'OFPAT_OUTPUT'},
		len     => $ofp->sizeof('ofp_action_output'),
		port    => $port_base,                          # send out eth1
		max_len => get_of_miss_send_len_default()
	};
	my $action_output = $ofp->pack( 'ofp_action_output', $action_output_args );

	my $pkt_sent = $packet_out . $action_output . $pkt->packed;

	# Send 'packet_out' message
	print $sock $pkt_sent;

	nftest_expect( 'eth1', $pkt->packed );

	# Wait for packet to be forwarded out
	sleep(.1);

}

run_black_box_test( \&my_test, \@ARGV );

