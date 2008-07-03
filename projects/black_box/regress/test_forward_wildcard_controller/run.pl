#!/usr/bin/perl -w
# test_forward_wildcard_controller

use strict;
use OF::Includes;

sub send_expect_exact {

	my ( $ofp, $sock, $in_port, $out_port, $max_idle, $pkt_len, $wildcards ) = @_;

	printf( "Wildcards are: %04x\n", $wildcards );

	# This packet will always match
	my $test_pkt = get_default_black_box_pkt_len( $in_port, $out_port, $pkt_len );

	# This packet will always miss
	my $test_pkt2 = get_default_black_box_pkt_len( $in_port + 5, $out_port + 5, $pkt_len );

	#print HexDump ( $test_pkt->packed );

	my $flow_mod_pkt =
	  create_flow_mod_from_udp( $ofp, $test_pkt, $in_port, $out_port, $max_idle, $wildcards );

	#print HexDump($flow_mod_pkt);

	# Send 'flow_mod' message
	print $sock $flow_mod_pkt;
	print "sent flow_mod message\n";
	usleep(100000);

	# Send a packet - ensure packet comes out desired port
	nftest_send( "eth" . ( $in_port + 1 ), $test_pkt->packed );

	print "Matching packet sent\n";
	my $recvd_mesg;
	sysread( $sock, $recvd_mesg, 1512 ) || die "Failed to receive message: $!";

	# Inspect  message
	my $msg_size = length($recvd_mesg);
	my $expected_size = $ofp->offsetof( 'ofp_packet_in', 'data' ) + length( $test_pkt->packed );

	#print "Comparing sizes $msg_size and $expected_size\n";
	compare( "msg size", $msg_size, '==', $expected_size );

	my $msg = $ofp->unpack( 'ofp_packet_in', $recvd_mesg );

	#print HexDump ($recvd_mesg);
	#print Dumper($msg);

	# Verify fields
	verify_header( $msg, 'OFPT_PACKET_IN', $msg_size );

	compare( "total len", $$msg{'total_len'}, '==', length( $test_pkt->packed ) );
	compare( "in_port",   $$msg{'in_port'},   '==', $in_port );
	compare( "reason",    $$msg{'reason'},    '==', $enums{'OFPR_ACTION'} );

	# verify packet was unchanged!
	my $recvd_pkt_data = substr( $recvd_mesg, $ofp->offsetof( 'ofp_packet_in', 'data' ) );
	if ( $recvd_pkt_data ne $test_pkt->packed ) {
		die "ERROR: received packet data didn't match packet sent\n";
	}

	nftest_send( "eth" . ( $in_port + 1 ), $test_pkt2->packed );

	print "Non-matching packet sent\n";
	sysread( $sock, $recvd_mesg, 1512 ) || die "Failed to receive message: $!";

	# Inspect  message
	$msg_size = length($recvd_mesg);
	$expected_size = $ofp->offsetof( 'ofp_packet_in', 'data' ) + length( $test_pkt2->packed );

	#print "Comparing sizes $msg_size and $expected_size\n";
	compare( "msg size", $msg_size, '==', $expected_size );

	$msg = $ofp->unpack( 'ofp_packet_in', $recvd_mesg );

	#print HexDump ($recvd_mesg);
	#print Dumper($msg);

	# Verify fields
	verify_header( $msg, 'OFPT_PACKET_IN', $msg_size );

	compare( "total len", $$msg{'total_len'}, '==', length( $test_pkt2->packed ) );
	compare( "in_port",   $$msg{'in_port'},   '==', $in_port );
	compare( "reason",    $$msg{'reason'},    '==', $enums{'OFPR_NO_MATCH'} );

	# verify packet was unchanged!
	$recvd_pkt_data = substr( $recvd_mesg, $ofp->offsetof( 'ofp_packet_in', 'data' ) );
	if ( $recvd_pkt_data ne $test_pkt2->packed ) {
		die "ERROR: received packet data didn't match packet sent\n";
	}

}

sub my_test {

	my ($sock, $options_ref) = @_;

	my $j = $enums{'OFPP_CONTROLLER'};

	enable_flow_expirations( $ofp, $sock );

	my $max_idle =  $$options_ref{'max_idle'};
	my $pkt_len = $$options_ref{'pkt_len'};
	my $pkt_total = $$options_ref{'pkt_total'};
	
	# send from every port to every other port
	for ( my $i = 0 ; $i < 4 ; $i++ ) {

		print "sending from $i to $j\n";

		#Very hackish, but basically iterate through the possibilities for
		#wildcarding one at a time.
		print "wildcards 0x0001 : IN_PORT\n";
		send_expect_exact( $ofp, $sock, $i, $j, $max_idle, $pkt_len, 0x0001 );
		wait_for_flow_expired( $ofp, $sock, $pkt_len, $pkt_total );

		#DL_VLAN fixed at 0xffff currently.
		#print "wildcards 0x0002 : DL_VLAN\n";
		#send_expect_exact( $ofp, $sock, $i, $j, $max_idle, $pkt_len, 0x0002);
		#wait_for_flow_expired( $ofp, $sock, $pkt_len, $pkt_total );

		print "wildcards 0x0004 : DL_SRC\n";
		send_expect_exact( $ofp, $sock, $i, $j, $max_idle, $pkt_len, 0x0004 );
		wait_for_flow_expired( $ofp, $sock, $pkt_len, $pkt_total );

		print "wildcards 0x0008 : DL_DST\n";
		send_expect_exact( $ofp, $sock, $i, $j, $max_idle, $pkt_len, 0x0008 );
		wait_for_flow_expired( $ofp, $sock, $pkt_len, $pkt_total );

		#DL_TYPE fixed at 0x0800 currently.
		#print "wildcards 0x0010 : DL_TYPE\n";
		#send_expect_exact( $ofp, $sock, $i, $j, $max_idle, $pkt_len, 0x0010);
		#wait_for_flow_expired( $ofp, $sock, $pkt_len, $pkt_total );

		print "wildcards 0x0020 : NW_SRC\n";
		send_expect_exact( $ofp, $sock, $i, $j, $max_idle, $pkt_len, 0x0020 );
		wait_for_flow_expired( $ofp, $sock, $pkt_len, $pkt_total );

		print "wildcards 0x0040 : NW_DST\n";
		send_expect_exact( $ofp, $sock, $i, $j, $max_idle, $pkt_len, 0x0040 );
		wait_for_flow_expired( $ofp, $sock, $pkt_len, $pkt_total );

		#NW_PROTO fixed at 17 currently.
		#print "wildcards 0x0080 : NW_PROTO\n";
		#send_expect_exact( $ofp, $sock, $i, $j, $max_idle, $pkt_len, 0x0080);
		#wait_for_flow_expired( $ofp, $sock, $pkt_len, $pkt_total );

		print "wildcards 0x0100 : TP_SRC\n";
		send_expect_exact( $ofp, $sock, $i, $j, $max_idle, $pkt_len, 0x0100 );
		wait_for_flow_expired( $ofp, $sock, $pkt_len, $pkt_total );

		print "wildcards 0x0200 : TP_SRC\n";
		send_expect_exact( $ofp, $sock, $i, $j, $max_idle, $pkt_len, 0x0200 );
		wait_for_flow_expired( $ofp, $sock, $pkt_len, $pkt_total );

	}
}

run_black_box_test( \&my_test, \@ARGV );

