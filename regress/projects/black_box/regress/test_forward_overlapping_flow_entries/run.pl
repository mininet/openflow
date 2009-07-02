#!/usr/bin/perl -w
# test_forward_overlapping_flow_entries

use strict;
use OF::Includes;

sub send_expect_multi_flow {

	my ( $ofp, $sock, $options_ref, $in_port_offset, $out_port_offset, $max_idle, $pkt_len ) = @_;

	my $in_port = $in_port_offset + $$options_ref{'port_base'};
	my $out_port = $out_port_offset + $$options_ref{'port_base'};

	my $test_pkt = get_default_black_box_pkt_len( $in_port, $out_port, $pkt_len );	

	#print HexDump ( $test_pkt->packed );

	my $wildcards = 0x0;    # exact match
	my $flags = $enums{'OFPFF_SEND_FLOW_REM'};

	my $flow_mod_pkt =
	  create_flow_mod_from_udp( $ofp, $test_pkt, $in_port,
		  $enums{'OFPP_ALL'}, $max_idle, $flags, $wildcards );

	#print HexDump($flow_mod_pkt);

	# Send 'flow_mod' message
	print $sock $flow_mod_pkt;
	print "sent exact match flow_mod message\n";
	
	# Give OF switch time to process the flow mod
	usleep($$options_ref{'send_delay'});
	
	$wildcards = 0x1fffff;    # wildcard everything

	# (send to controller)
	$flow_mod_pkt = create_flow_mod_from_udp( $ofp, $test_pkt, $in_port,
		$enums{'OFPP_CONTROLLER'}, 2, $flags, $wildcards );

	#print HexDump($flow_mod_pkt);

	# Send 'flow_mod' message
	print $sock $flow_mod_pkt;
	print "sent wildcard match flow_mod message\n";

	# Give OF switch time to process the flow mod
	usleep($$options_ref{'send_delay'});

	# Send a packet - ensure packet comes out desired port
	nftest_send( "eth" . ( $in_port_offset + 1 ), $test_pkt->packed );

	for ( my $k = 0 ; $k < $$options_ref{'num_ports'}; $k++ ) {
		if ( $k != $in_port_offset ) {
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

	my $num_ports = $$options_ref{'num_ports'};

	my $j = 0;

	# send from every port, receive on every port except the send port
	#for ( my $i = 0 ; $i < $num_ports ; $i++ ) {
		my $i = 0;
		my $j = ($i + 1) % $num_ports;
		print "sending from $i to (all ports but $i)\n";
		send_expect_multi_flow( $ofp, $sock, $options_ref, $i, $j, $max_idle, $pkt_len );
		print "waiting for first flow to expire\n";
		wait_for_flow_expired( $ofp, $sock, $options_ref, $pkt_len, 0 );
		print "waiting for second flow to expire\n";
		wait_for_flow_expired( $ofp, $sock, $options_ref, $pkt_len, $pkt_total );
	#}
}

run_black_box_test( \&my_test, \@ARGV );

