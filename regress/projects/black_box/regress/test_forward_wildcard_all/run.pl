#!/usr/bin/perl -w
# test_forward_wildcard_all

use strict;
use OF::Includes;

sub forward_wc_all {

	forward_simple(@_, 'all');
}

sub forward_wc_all_vlan {
        my $vlan_id = 0x25ae;
                #[15:13] priority, [11:0] vlan id
		#The value was chosen at random
        forward_simple(@_, 'all', undef, undef, $vlan_id);
}

sub my_test {

	my ( $sock, $options_ref ) = @_;

	for_all_wildcards( $ofp, $sock, $options_ref, \&forward_wc_all);
	if ( not defined( $$options_ref{'no_vlan'} ) ) {
	    for_all_wildcards( $ofp, $sock, $options_ref, \&forward_wc_all_vlan);
	}
}

run_black_box_test( \&my_test, \@ARGV );

#sub send_expect_exact {
#
#	my ( $ofp, $sock, $options_ref, $in_port_offset, $out_port_offset, $wildcards ) = @_;
#
#	my $in_port = $in_port_offset + $$options_ref{'port_base'};
#	my $out_port = $enums{'OFPP_ALL'};    # all physical ports except the input
#
#	printf( "Wildcards are: %04x\n", $wildcards );
#
#	# in_port refers to the flow mod entry's input
#
#	# This packet will always match
#	my $test_pkt = get_default_black_box_pkt_len( $in_port, $out_port, $$options_ref{'pkt_len'} );
#
#	# This packet will always miss
#	my $test_pkt2 = get_default_black_box_pkt_len( $in_port + 5, $out_port + 5, $$options_ref{'pkt_len'} );
#
#	print HexDump ( $test_pkt->packed );
#	print HexDump ( $test_pkt2->packed );
#
#	my $flow_mod_pkt =
#	  create_flow_mod_from_udp( $ofp, $test_pkt, $in_port, $out_port, $$options_ref{'max_idle'}, $wildcards );
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
#	nftest_send( "eth" . ( $in_port_offset + 1 ), $test_pkt->packed );
#
#	for ( my $k = 0 ; $k < $$options_ref{'num_ports'} ; $k++ ) {
#		if ( $k != $in_port_offset ) {
#			nftest_expect( "eth" . ( $k + 1 ), $test_pkt->packed );
#		}
#	}
#
#	print "Matching packet sent\n";
#
#	#nftest_send( "eth" . ( $in_port_offset + 1 ), $test_pkt2->packed );
#
##	#print "Non-matching packet sent\n";
##	my $recvd_mesg;
##	sysread( $sock, $recvd_mesg, 1512 ) || die "Failed to receive message: $!";
##
##	# Inspect  message
##	my $msg_size = length($recvd_mesg);
##	my $expected_size = $ofp->offsetof( 'ofp_packet_in', 'data' ) + length( $test_pkt2->packed );
##
##	print HexDump ($recvd_mesg);
##
##	#print "Comparing sizes $msg_size and $expected_size\n";
##	compare( "msg size", $msg_size, '==', $expected_size );
##
##	my $msg = $ofp->unpack( 'ofp_packet_in', $recvd_mesg );
##
##	#print HexDump ($recvd_mesg);
##	#print Dumper($msg);
##
##	# Verify fields
##	verify_header( $msg, 'OFPT_PACKET_IN', $msg_size );
##
##	compare( "total len", $$msg{'total_len'}, '==', length( $test_pkt2->packed ) );
##	compare( "in_port",   $$msg{'in_port'},   '==', $in_port );
##	compare( "reason",    $$msg{'reason'},    '==', $enums{'OFPR_NO_MATCH'} );
##
##	# verify packet was unchanged!
##	my $recvd_pkt_data = substr( $recvd_mesg, $ofp->offsetof( 'ofp_packet_in', 'data' ) );
##	if ( $recvd_pkt_data ne $test_pkt2->packed ) {
##		die "ERROR: received packet data didn't match packet sent\n";
##	}
#
#}
#
#sub my_test {
#
#	my ( $sock, $options_ref ) = @_;
#	my $j = $enums{'OFPP_FLOOD'};
#
#	my $max_idle =  $$options_ref{'max_idle'};
#	my $pkt_len = $$options_ref{'pkt_len'};
#	my $pkt_total = $$options_ref{'pkt_total'};
#
#	# send from every port to every other port
#	for ( my $i = 0 ; $i < 4 ; $i++ ) {
#
#		print "sending from $i to $j\n";
#
#		#Very hackish, but basically iterate through the possibilities for
#		#wildcarding one at a time.
#		print "wildcards 0x0001 : IN_PORT\n";
#		send_expect_exact( $ofp, $sock, $options_ref, $i, $j, 0x0001 );
#		wait_for_flow_expired_all( $ofp, $sock, $options_ref );
#
#		#DL_VLAN fixed at 0xffff currently.
#		#print "wildcards 0x0002 : DL_VLAN\n";
#		#send_expect_exact( $ofp, $sock, $options_ref, $i, $j, 0x0002);
#		#wait_for_flow_expired_all( $ofp, $sock, $options_ref );
#
#		print "wildcards 0x0004 : DL_SRC\n";
#		send_expect_exact( $ofp, $sock, $options_ref, $i, $j, 0x0004 );
#		wait_for_flow_expired_all( $ofp, $sock, $options_ref );
#
#		print "wildcards 0x0008 : DL_DST\n";
#		send_expect_exact( $ofp, $sock, $options_ref, $i, $j, 0x0008 );
#		wait_for_flow_expired_all( $ofp, $sock, $options_ref );
#
#		#DL_TYPE fixed at 0x0800 currently.
#		#print "wildcards 0x0010 : DL_TYPE\n";
#		#send_expect_exact( $ofp, $sock, $options_ref, $i, $j, 0x0010);
#		#wait_for_flow_expired_all( $ofp, $sock, $options_ref );
#
#		print "wildcards 0x0020 : NW_SRC\n";
#		send_expect_exact( $ofp, $sock, $options_ref, $i, $j, 0x0020 );
#		wait_for_flow_expired_all( $ofp, $sock, $options_ref );
#
#		print "wildcards 0x0040 : NW_DST\n";
#		send_expect_exact( $ofp, $sock, $options_ref, $i, $j, 0x0040 );
#		wait_for_flow_expired_all( $ofp, $sock, $options_ref );
#
#		#NW_PROTO fixed at 17 currently.
#		#print "wildcards 0x0080 : NW_PROTO\n";
#		#send_expect_exact( $ofp, $sock, $options_ref, $i, $j, 0x0080);
#		#wait_for_flow_expired_all( $ofp, $sock, $options_ref );
#
#		print "wildcards 0x0100 : TP_SRC\n";
#		send_expect_exact( $ofp, $sock, $options_ref, $i, $j, 0x0100 );
#		wait_for_flow_expired_all( $ofp, $sock, $options_ref );
#
#		print "wildcards 0x0200 : TP_SRC\n";
#		send_expect_exact( $ofp, $sock, $options_ref, $i, $j, 0x0200 );
#		wait_for_flow_expired_all( $ofp, $sock, $options_ref );
#
#	}
#}
#
#run_black_box_test( \&my_test, \@ARGV );
#
