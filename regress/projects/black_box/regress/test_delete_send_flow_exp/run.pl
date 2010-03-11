#!/usr/bin/perl -w
# test_delete

use strict;
use OF::Includes;

sub my_test {

	my ($sock, $options_ref) = @_;
	
	my $in_port = $$options_ref{'port_base'};
	my $out_port = $in_port + 1;
	
	my $test_pkt = get_default_black_box_pkt( $in_port, $out_port, $$options_ref{'pkt_len'} );

	my $max_idle = 0x0; # second before flow expiration -- never time out
	my $wildcards = 0x0;    # exact match
	# Create a flow mod without expiry
	my $flags = 0x0;        # don't send flow expiry
	my $flow_mod_pkt =
	  create_flow_mod_from_udp( $ofp, $test_pkt, $in_port, $out_port, $max_idle, $flags, $wildcards );
	print "send flow mode without expiry\n";
	print $sock $flow_mod_pkt;

	# Delete the flow and verify that we don't see an expiry
	$flow_mod_pkt =
	  create_flow_mod_from_udp_action( $ofp, $test_pkt, $in_port, $out_port, $max_idle,
		$flags, $wildcards, "OFPFC_DELETE" );
	print $sock $flow_mod_pkt;

	my $sel = IO::Select->new($sock);
	if ($sel->can_read(2)) {
		print "Error: was not expecting a message from the switch\n";
		exit 1;
	}
	
	# Create a flow mod with expiry
	$flags = $enums{'OFPFF_SEND_FLOW_REM'}; # want flow expiry
	$flow_mod_pkt =
	  create_flow_mod_from_udp( $ofp, $test_pkt, $in_port, $out_port, $max_idle, $flags, $wildcards );
	print "send flow mode with expiry\n";
	print $sock $flow_mod_pkt;

	# Delete the flow and verify that we do see an expiry
	$flags = 0x0; # Reset the flags to zero. Should not matter as it 
	              # should only depend on the flags when the flow was installed.
	$flow_mod_pkt =
	  create_flow_mod_from_udp_action( $ofp, $test_pkt, $in_port, $out_port, $max_idle,
		$flags, $wildcards, "OFPFC_DELETE" );
	print $sock $flow_mod_pkt;

	my $pkt_len   = 0;
	my $pkt_total = 0;
	wait_for_flow_expired( $ofp, $sock, $options_ref, $pkt_len, $pkt_total );

	# Redo the same test with a few packets to make sure stats are correct
	# Jean II

	# Create a flow mod with expiry
	$flags = $enums{'OFPFF_SEND_FLOW_REM'}; # want flow expiry
	$flow_mod_pkt =
	  create_flow_mod_from_udp( $ofp, $test_pkt, $in_port, $out_port, $max_idle, $flags, $wildcards );
	print "send flow mode with expiry and with 3 packets\n";
	print $sock $flow_mod_pkt;

	# Give OF switch time to process the flow mod
	usleep($$options_ref{'send_delay'});
	usleep($$options_ref{'send_delay'});

	# Send 3 packets, because first packet can be "special" - Jean II
	# We should be using $options{'pkt_total'}, but that is stuck at 1
	nftest_send("eth" . ($in_port), $test_pkt->packed);
	nftest_send("eth" . ($in_port), $test_pkt->packed);
	nftest_send("eth" . ($in_port), $test_pkt->packed);

	# expect 3 packets
	print "expect 3 packets\n";
	nftest_expect("eth" . ($out_port), $test_pkt->packed);
	nftest_expect("eth" . ($out_port), $test_pkt->packed);
	nftest_expect("eth" . ($out_port), $test_pkt->packed);

	# Wait for stats to refresh
	sleep($$options_ref{'max_idle'});
	#dpctl_show_flows($options_ref);

	# Delete the flow and verify that we do see an expiry
	$flags = 0x0; # Reset the flags to zero. Should not matter as it
	              # should only depend on the flags when the flow was installed.
	$flow_mod_pkt =
	  create_flow_mod_from_udp_action( $ofp, $test_pkt, $in_port, $out_port, $max_idle,
		$flags, $wildcards, "OFPFC_DELETE" );
	print $sock $flow_mod_pkt;

	# And now check the stats in the flow removed message...
	my $pkt_len   = $$options_ref{'pkt_len'};
	my $pkt_total = 3;
	wait_for_flow_expired( $ofp, $sock, $options_ref, $pkt_len, $pkt_total );



}

run_black_box_test( \&my_test, \@ARGV );

