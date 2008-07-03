#!/usr/bin/perl -w
# test_forward_overlapping_flow_entries

use strict;
use OF::Includes;

sub send_expect_multi_flow {

	my ( $ofp, $sock, $in_port, $out_port, $max_idle, $pkt_len ) = @_;

	my $test_pkt = get_default_black_box_pkt_len( $in_port, $out_port, $pkt_len );	

	#print HexDump ( $test_pkt->packed );

	my $wildcards = 0x0;    # exact match

	my $flow_mod_pkt =
	  create_flow_mod_from_udp( $ofp, $test_pkt, $in_port, $out_port, $max_idle, $wildcards );

	#print HexDump($flow_mod_pkt);

	# Send 'flow_mod' message
	print $sock $flow_mod_pkt;
	print "sent exact match flow_mod message\n";
	usleep(100000);

	$wildcards = 0x03ff;    # wildcard everything

	$flow_mod_pkt = create_flow_mod_from_udp( $ofp, $test_pkt, $in_port, 0xfffd, 1, $wildcards );

	#print HexDump($flow_mod_pkt);

	# Send 'flow_mod' message
	print $sock $flow_mod_pkt;
	print "sent wildcard match flow_mod message\n";
	usleep(100000);

	# Send a packet - ensure packet comes out desired port
	nftest_send( "eth" . ( $in_port + 1 ), $test_pkt->packed );

	for ( my $k = 0 ; $k < 4 ; $k++ ) {
		if ( $k + 1 != $in_port + 1 ) {
			nftest_expect( "eth" . ( $k + 1 ), $test_pkt->packed );
		}
	}

}

sub my_test {

	my ($sock, $options_ref) = @_; 
	
	#my $max_idle =  $$options_ref{'max_idle'};
	my $max_idle = 5;
	my $pkt_len = $$options_ref{'pkt_len'};
	my $pkt_total = $$options_ref{'pkt_total'};

	enable_flow_expirations( $ofp, $sock );

	my $j = $enums{'OFPP_ALL'};

	# send from every port, receive on every port except the send port
	for ( my $i = 0 ; $i < 4 ; $i++ ) {
		print "sending from $i to (all ports but $i)\n";
		send_expect_multi_flow( $ofp, $sock, $i, $j, $max_idle, $pkt_len );
		print "waiting for first flow to expire\n";
		wait_for_flow_expired( $ofp, $sock, $pkt_len, 0 );
		print "waiting for second flow to expire\n";
		wait_for_flow_expired( $ofp, $sock, $pkt_len, $pkt_total );
	}
}

run_black_box_test( \&my_test, \@ARGV );

