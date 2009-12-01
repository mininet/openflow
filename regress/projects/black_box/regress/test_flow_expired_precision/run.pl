#!/usr/bin/perl -w
# test_flow_expired
# This test assumes a lightly loaded switch that can expire flows within a
# reasonably tight bound (<1s) of the specified hard timeout value.

use strict;
use OF::Includes;

sub my_test {

	my ( $sock, $options_ref ) = @_;

	my $in_port  = $$options_ref{'port_base'};
	my $out_port = $in_port + 1;

	my $test_pkt = get_default_black_box_pkt( $in_port, $out_port );

	my $max_idle  = 0x1;    # second before flow expiration
	my $wildcards = 0x0;    # exact match
	my $flags        = $enums{'OFPFF_SEND_FLOW_REM'};    # want flow expiry
	my $flow_mod_pkt =
	  create_flow_mod_from_udp( $ofp, $test_pkt, $in_port, $out_port, $max_idle,
		$flags, $wildcards );

	#print HexDump($pkt);

	# Send 'flow_mod' message
	print $sock $flow_mod_pkt;

	my $pkt_len   = 0;
	my $pkt_total = 0;

	my $read_size = 1512;

	my $recvd_mesg;
	sysread( $sock, $recvd_mesg, $read_size )
	  || die "Failed to receive ofp_flow_removed message: $!";

	# Inspect  message
	my $msg_size      = length($recvd_mesg);
	my $expected_size = $ofp->sizeof('ofp_flow_removed');
	compare( "ofp_flow_removed msg size",
		length($recvd_mesg), '==', $expected_size );

	my $msg = $ofp->unpack( 'ofp_flow_removed', $recvd_mesg );

	print Dumper($msg);

	compare( "ofp_flow_removed packet_count",
		$$msg{'packet_count'}, '==', $pkt_total );
	if ( $$msg{'duration_sec'} != 1 ) {
		die "Error, duration_sec out of acceptable range";
	}
	if ( $$msg{'duration_nsec'} == 0 ) {
		die "Error, duration_nsec out of acceptable range";
	}

}

run_black_box_test( \&my_test, \@ARGV );

