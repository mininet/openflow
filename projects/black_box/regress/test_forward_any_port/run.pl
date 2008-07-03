#!/usr/bin/perl -w
# test_forward_any_port

use strict;
use OF::Includes;

sub send_expect_exact {

	my ( $ofp, $sock, $in_port, $out_port, $options_ref ) = @_;

	my $test_pkt = get_default_black_box_pkt_len( $in_port, $out_port, $$options_ref{'pkt_len'} );

	#print HexDump ( $test_pkt->packed );

	my $wildcards = 0x3ff;    # all fields wildcarded!

	my $flow_mod_pkt =
	  create_flow_mod_from_udp( $ofp, $test_pkt, $in_port, $out_port, $$options_ref{'max_idle'}, $wildcards );

	#print HexDump($flow_mod_pkt);

	# Send 'flow_mod' message
	print $sock $flow_mod_pkt;
	print "sent flow_mod message\n";
	usleep(100000);

	nftest_send( "eth" . ( $in_port + 1 ), $test_pkt->packed );
	nftest_expect( "eth" . ( $out_port + 1 ), $test_pkt->packed );
}

sub my_test {

	my ( $sock, $options_ref ) = @_;

	enable_flow_expirations( $ofp, $sock );

	# send from every port to every other port
	for ( my $i = 0 ; $i < 4 ; $i++ ) {
		for ( my $j = 0 ; $j < 4 ; $j++ ) {
			if ( $i != $j ) {
				print "sending from $i to $j\n";
				send_expect_exact( $ofp, $sock, $i, $j, $options_ref );
				wait_for_flow_expired( $ofp, $sock, $$options_ref{'pkt_len'}, $$options_ref{'pkt_total'} );
			}
		}
	}
}

run_black_box_test( \&my_test, \@ARGV );

