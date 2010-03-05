#!/usr/bin/perl -w
# test_packet_in

use strict;
use OF::Includes;

sub my_test {

	my ($sock, $options_ref) = @_;

	my $in_port = $$options_ref{'port_base'};
	my $out_port = $in_port + 1;

	my $pkt = get_default_black_box_pkt( $in_port, $out_port);
	nftest_send('eth1', $pkt->packed );
	print "Sent test packet...\n";

	my $recvd_mesg;
	sysread( $sock, $recvd_mesg, 1512 ) || die "Failed to receive message: $!";

	# Inspect  message
	my $msg_size = length($recvd_mesg);
	my $expected_size = $ofp->offsetof( 'ofp_packet_in', 'data' ) + length( $pkt->packed );
	compare( "msg size", $msg_size, '==', $expected_size );

	my $msg = $ofp->unpack( 'ofp_packet_in', $recvd_mesg );

	#print HexDump ($recvd_mesg);
	#print Dumper($msg);

	# Verify fields
	verify_header( $msg, 'OFPT_PACKET_IN', $msg_size );

	compare( "total len", $$msg{'total_len'}, '==', length( $pkt->packed ) );
	compare( "in_port",   $$msg{'in_port'},   '==', $in_port );
	compare( "reason",    $$msg{'reason'},    '==', $enums{'OFPR_NO_MATCH'} );

	# verify packet was unchanged!
	my $recvd_pkt_data = substr( $recvd_mesg, $ofp->offsetof( 'ofp_packet_in', 'data' ) );
	if ( $recvd_pkt_data ne $pkt->packed ) {
		die "ERROR: received packet data didn't match packet sent\n";
	}
}

run_black_box_test( \&my_test, \@ARGV );
