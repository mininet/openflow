#!/usr/bin/perl -w
# test_flow_expired

use strict;
use OF::Includes;

sub my_test {

	my ($sock, $options_ref) = @_;

	my $in_port = $$options_ref{'port_base'};
	my $out_port = $in_port + 1;

	my $test_pkt = get_default_black_box_pkt( $in_port, $out_port);

	my $max_idle = 0x1; # second before flow expiration
	my $wildcards = 0x0;    # exact match
	my $flags = $enums{'OFPFF_SEND_FLOW_REM'}; # want flow expiry
	my $cookie = 0x123456;
	# Create a flow mod with a flow cookie
	my $flow_mod_pkt =
		create_flow_mod_from_udp( $ofp, $test_pkt, $in_port, $out_port,
			$max_idle, $flags, $wildcards, undef, undef, undef,
			undef, $cookie );

	#print HexDump($pkt);

	# Send 'flow_mod' message
	print $sock $flow_mod_pkt;

	my $pkt_len   = 0;
	my $pkt_total = 0;
	wait_for_flow_expired( $ofp, $sock, $options_ref, $pkt_len,
		$pkt_total, undef, $cookie );

}

run_black_box_test( \&my_test, \@ARGV );

