#!/usr/bin/perl -w
# test_flow_expired

use strict;
use OF::Includes;
use IO::Select;

sub my_test {

	my ($sock, $options_ref) = @_;
	
	my $in_port = $$options_ref{'port_base'};
	my $out_port = $in_port + 1;
	
	my $test_pkt = get_default_black_box_pkt( $in_port, $out_port);

	my $max_idle = 0x1; # second before flow expiration
	my $wildcards = 0x0;    # exact match
	# Create a flow mod without expiry
	my $flags = 0x0;        # don't send flow expiry
	my $flow_mod_pkt =
	  create_flow_mod_from_udp( $ofp, $test_pkt, $in_port, $out_port, $max_idle, $flags, $wildcards );
	print $sock $flow_mod_pkt;

	my $sel = IO::Select->new($sock);
	if ($sel->can_read(2 * $max_idle)) {
		print "Error: was not expecting a message from the switch\n";
		exit 1;
	}
	
      	# Create a flow mod with expiry
	$flags = $enums{'OFPFF_SEND_FLOW_REM'}; # want flow expiry
	$flow_mod_pkt =
	  create_flow_mod_from_udp( $ofp, $test_pkt, $in_port, $out_port, $max_idle, $flags, $wildcards );
	print $sock $flow_mod_pkt;

	my $pkt_len   = 0;
	my $pkt_total = 0;
	wait_for_flow_expired( $ofp, $sock, $options_ref, $pkt_len, $pkt_total );

}

run_black_box_test( \&my_test, \@ARGV );

