#!/usr/bin/perl -w
# test_forward_wildcard_port

use strict;
use OF::Includes;

sub forward_wc_port {

	forward_simple(@_, 'port');
}

sub forward_wc_port_vlan {
        my $vlan_id = 0x8ea5;
                #[15:13] priority, [11:0] vlan id
		#The value was chosen at random
        forward_simple(@_, 'port', undef, undef, $vlan_id);
}

sub my_test {

	my ( $sock, $options_ref ) = @_;

	for_all_wildcards( $ofp, $sock, $options_ref, \&forward_wc_port);
	if ( not defined( $$options_ref{'no_vlan'} ) ) {
	    for_all_wildcards( $ofp, $sock, $options_ref, \&forward_wc_port_vlan);
	}
}

run_black_box_test( \&my_test, \@ARGV );

#sub send_expect_exact {
#
#	my ( $ofp, $sock, $options_ref, $in_port_offset, $out_port_offset, $max_idle, $pkt_len, $wildcards ) = @_;
#
#	my $in_port = $in_port_offset + $$options_ref{'port_base'};
#	my $out_port = $out_port_offset + $$options_ref{'port_base'};	
#
#	printf( "Wildcards are: %04x\n", $wildcards );
#
#	# This packet will always match
#	my $test_pkt = get_default_black_box_pkt_len( $in_port, $out_port, $pkt_len );
#
#	# This packet will always miss
#	my $test_pkt2 = get_default_black_box_pkt_len( $in_port + 5, $out_port + 5, $pkt_len );
#
#	#print HexDump ( $test_pkt->packed );
#
#	my $flow_mod_pkt =
#	  create_flow_mod_from_udp( $ofp, $test_pkt, $in_port, $out_port, $max_idle, $wildcards );
#
#	#print HexDump($flow_mod_pkt);
#
#	# Send 'flow_mod' message
#	print $sock $flow_mod_pkt;
#	print "sent flow_mod message\n";
#	
#	# Give OF switch time to process the flow mod
#	usleep($$options_ref{'send_delay'});
#
#	# Send a packet - ensure packet comes out desired port
#	nftest_send( "eth" . ($in_port_offset + 1), $test_pkt->packed );
#	nftest_expect( "eth" . ( $out_port_offset + 1 ), $test_pkt->packed );
#	print "Matching packet sent\n";
#
#	nftest_send( "eth" . ($in_port_offset + 1), $test_pkt2->packed );
#
#	print "Non-matching packet sent\n";
#	my $recvd_mesg;
#	sysread( $sock, $recvd_mesg, 1512 ) || die "Failed to receive message: $!";
#
#	# Inspect  message
#	my $msg_size = length($recvd_mesg);
#	my $expected_size = $ofp->offsetof( 'ofp_packet_in', 'data' ) + length( $test_pkt2->packed );
#
#	#print "Comparing sizes $msg_size and $expected_size\n";
#	compare( "msg size", $msg_size, '==', $expected_size );
#
#	my $msg = $ofp->unpack( 'ofp_packet_in', $recvd_mesg );
#
#	#print HexDump ($recvd_mesg);
#	#print Dumper($msg);
#
#	# Verify fields
#	verify_header( $msg, 'OFPT_PACKET_IN', $msg_size );
#
#	compare( "total len", $$msg{'total_len'}, '==', length( $test_pkt2->packed ) );
#	compare( "in_port",   $$msg{'in_port'},   '==', $in_port );
#	compare( "reason",    $$msg{'reason'},    '==', $enums{'OFPR_NO_MATCH'} );
#
#	# verify packet was unchanged!
#	my $recvd_pkt_data = substr( $recvd_mesg, $ofp->offsetof( 'ofp_packet_in', 'data' ) );
#	if ( $recvd_pkt_data ne $test_pkt2->packed ) {
#		die "ERROR: received packet data didn't match packet sent\n";
#	}
#
#}

