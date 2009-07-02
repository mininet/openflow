#!/usr/bin/perl -w
# test_forward_after_expiration

use strict;
use OF::Includes;

sub send_expect_exact {

	my ( $ofp, $sock, $options_ref, $in_port_offset, $out_port_offset ) = @_;

	my $in_port = $in_port_offset + $$options_ref{'port_base'};
	my $out_port = $out_port_offset + $$options_ref{'port_base'};

	my $test_pkt = get_default_black_box_pkt_len( $in_port, $out_port, $$options_ref{'pkt_len'} );

	#print HexDump ( $test_pkt->packed );

	my $wildcards = 0x0;    # exact match
	my $flags = $enums{'OFPFF_SEND_FLOW_REM'};

	my $flow_mod_pkt =
	  create_flow_mod_from_udp( $ofp, $test_pkt, $in_port, $out_port,
		  $$options_ref{'max_idle'}, $flags, $wildcards );

	#print HexDump($flow_mod_pkt);

	# Send 'flow_mod' message
	print $sock $flow_mod_pkt;
	print "sent flow_mod message\n";

	# Give OF switch time to process the flow mod
	usleep($$options_ref{'send_delay'});

	# Send a packet - ensure packet comes out desired port
	nftest_send( "eth" . ( $in_port_offset + 1 ), $test_pkt->packed );
	nftest_expect( "eth" . ( $out_port_offset + 1 ), $test_pkt->packed );
}

sub send_expect_secchan_nomatch {

	my ( $ofp, $sock, $options_ref, $in_port_offset, $out_port_offset, $max_idle, $pkt_len ) = @_;

	my $in_port = $in_port_offset + $$options_ref{'port_base'};
	my $out_port = $out_port_offset + $$options_ref{'port_base'};

	my $test_pkt2 = get_default_black_box_pkt_len( $in_port, $out_port, $$options_ref{'pkt_len'} );

	print "sending out eth"
	  . ( $in_port_offset + 1 )
	  . ", expecting response on secchan due to no flow matching\n";

	# Send a packet - ensure packet comes out desired port
	nftest_send( "eth" . ( $in_port_offset + 1 ), $test_pkt2->packed );

	my $recvd_mesg;
	sysread( $sock, $recvd_mesg, 1512 ) || die "Failed to receive message: $!";

	# Inspect  message
	my $msg_size = length($recvd_mesg);
	my $expected_size = $ofp->offsetof( 'ofp_packet_in', 'data' ) + length( $test_pkt2->packed );
	compare( "msg size", $msg_size, '==', $expected_size );

	my $msg = $ofp->unpack( 'ofp_packet_in', $recvd_mesg );

	#print HexDump ($recvd_mesg);
	#print Dumper($msg);

	# Verify fields

	print "Verifying secchan message for packet sent in to eth" . ( $in_port_offset + 1 ) . "\n";

	verify_header( $msg, 'OFPT_PACKET_IN', $msg_size );

	compare( "total len", $$msg{'total_len'}, '==', length( $test_pkt2->packed ) );
	compare( "in_port",   $$msg{'in_port'},   '==', $in_port );
	compare( "reason",    $$msg{'reason'},    '==', $enums{'OFPR_NO_MATCH'} );

	# verify packet was unchanged!
	my $recvd_pkt_data = substr( $recvd_mesg, $ofp->offsetof( 'ofp_packet_in', 'data' ) );
	if ( $recvd_pkt_data ne $test_pkt2->packed ) {
		die "ERROR: sending from eth"
		  . $in_port + 1
		  . " received packet data didn't match packet sent\n";
	}

}

sub test_forward_after_expiration {

	my ( $ofp, $sock, $options_ref, $i, $j, $wildcards ) = @_;

	my $max_idle =  $$options_ref{'max_idle'};
	my $pkt_len = $$options_ref{'pkt_len'};
	my $pkt_total = $$options_ref{'pkt_total'};

	send_expect_exact( $ofp, $sock, $options_ref, $i, $j);
	print "waiting for flow to expire\n";
	wait_for_flow_expired_all( $ofp, $sock, $options_ref );
	usleep($$options_ref{'send_delay'});
	send_expect_secchan_nomatch( $ofp, $sock, $options_ref, $i, $j);
}

sub my_test {

	my ($sock, $options_ref) = @_;

	# send from every port to every other port
	for_all_port_pairs( $ofp, $sock, $options_ref, \&test_forward_after_expiration, 0x0);
}

run_black_box_test( \&my_test, \@ARGV );
