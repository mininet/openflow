#!/usr/bin/perl -w
# test_forward_exact_all

use strict;
use OF::Includes;

sub send_expect_multiple {

	my ( $ofp, $sock, $in_port, $out_port, $options_ref ) = @_;

	my $test_pkt = get_default_black_box_pkt_len( $in_port, $out_port, $$options_ref{'pkt_len'} );

	#print HexDump ( $test_pkt->packed );

	my $wildcards = 0x0;    # exact match

	my $flow_mod_pkt =
	  create_flow_mod_from_udp( $ofp, $test_pkt, $in_port, $out_port, $$options_ref{'max_idle'}, $wildcards );

	#print HexDump($flow_mod_pkt);

	# Send 'flow_mod' message
	print $sock $flow_mod_pkt;
	print "sent flow_mod message\n";
	usleep(100000);

	nftest_send( "eth" . ( $in_port + 1 ), $test_pkt->packed );

	for ( my $k = 0 ; $k < 4 ; $k++ ) {
		if ( $k + 1 != $in_port + 1 ) {
			nftest_expect( "eth" . ( $k + 1 ), $test_pkt->packed );
		}
	}
}

sub my_test {

	my ( $sock, $options_ref ) = @_;
	my $j = $enums{'OFPP_ALL'};    # all physical ports except the input

	enable_flow_expirations( $ofp, $sock );

	# send from every port, receive on every port except the send port
	for ( my $i = 0 ; $i < 4 ; $i++ ) {
		print "sending from $i to (all ports but $i)\n";
		send_expect_multiple( $ofp, $sock, $i, $j, $options_ref );
		wait_for_flow_expired( $ofp, $sock, $$options_ref{'pkt_len'}, $$options_ref{'pkt_total'} );
	}
}

run_black_box_test( \&my_test, \@ARGV );

