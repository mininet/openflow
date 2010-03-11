#!/usr/bin/perl -w
# test_emergency_table

use strict;
use OF::Includes;
use OF::OFUtil;

sub test_emergency_cache_first {
	my ( $ofp, $sock, $options_ref, $i, $j, $wildcards ) = @_;

	my $max_idle = $$options_ref{'max_idle'};
	my $pkt_len  = $$options_ref{'pkt_len'};
	my $in_port  = $i + $$options_ref{'port_base'};
	my $out_port = $j + $$options_ref{'port_base'};
	my $test_pkt_args = {
		DA     => "00:00:00:00:00:" . sprintf( "%02d", $out_port ),
		SA     => "00:00:00:00:00:" . sprintf( "%02d", $in_port ),
		src_ip => "192.168.200." .           ( $in_port ),
		dst_ip => "192.168.201." .           ( $out_port ),
		ttl    => 64,
		len    => $pkt_len,
		src_port => 70,
		dst_port => 80
	};
	my $test_pkt = new NF2::UDP_pkt(%$test_pkt_args);

	print "Set both normal and emergency flow table. Normal key must win\n";

	# 1st flow entry -- exact match, normal flow table
	my $max_idle_no_expire = 0;
	my $normal_wildcards = 0x0;    # exact match
	my $normal_flags = $enums{'OFPFF_SEND_FLOW_REM'}; # want flow expiry
	my $flow_mod_normal_pkt =
          create_flow_mod_from_udp( $ofp, $test_pkt, $in_port, $out_port, $max_idle_no_expire, $normal_flags, $normal_wildcards );

	# 2nd flow entry -- wildcard match all, emergency flow table
	my $emergency_wildcards =  $enums{'OFPFW_ALL'};     # wildcard match all to the all ports
	my $emergency_flags = $enums{'OFPFF_EMERG'};
	my $flow_mod_emergency_pkt =
	  create_flow_mod_from_udp( $ofp, $test_pkt, $in_port, $enums{'OFPP_ALL'}, $max_idle_no_expire, $emergency_flags, $emergency_wildcards );

	#print HexDump($flow_mod_normal_pkt);
	#print HexDump($flow_mod_emergency_pkt);

	# Send 'flow_mod' message
	print $sock $flow_mod_normal_pkt;
	print "sent flow_mod message (normal table)\n";

	# Give OF switch time to process the flow mod
	usleep($$options_ref{'send_delay'});

	# Send 2nd 'flow_mod' message
	print $sock $flow_mod_emergency_pkt;
	print "sent flow_mod message (emergency table)\n";
	
	# Give OF switch time to process the flow mod
	usleep($$options_ref{'send_delay'});

	# Send a packet - ensure packet comes out desired port
	print "Verify packets are forwarded correctly\n";
	nftest_send( "eth" . ( $i + 1 ), $test_pkt->packed );
	nftest_expect( "eth" . ( $j + 1 ), $test_pkt->packed );

        # Wait for ECHO_REQUEST but don't reply so that ofprotocol notices disconnection.
        wait_for_echo_request ( $ofp, $sock, $options_ref, $ofp->sizeof('ofp_header'));
	return $test_pkt;
}

sub test_emergency_cache_second {
        my ( $test_pkt, $options_ref, $i, $j ) = @_;

	print "sending from $i to $j, but expect the packet from all ports\n";
	nftest_send( "eth" . ( $i + 1 ), $test_pkt->packed );

	# expect packets on all other interfaces
	print "expect multiple packets\n";

	for ( my $k = 0 ; $k < $$options_ref{'num_ports'} ; $k++ ) {
		if ( $k != $i ) {
			nftest_expect( "eth" . ( $k + 1), $test_pkt->packed );
		}
	}
}

sub my_test {
	my ($sock, $options_ref) = @_;

	if ( not defined( $$options_ref{'no_emerg'} ) ) {
		#This test uses two ports
		my $inport = 0;
		my $outport = 1;
		my $wildcards = 0; #exact match

		# Wait until switch notices disconnection. it depends on implementation
		my $wait_timer = 20;

		my $test_pkt = test_emergency_cache_first($ofp, $sock, $options_ref, $inport, $outport, $wildcards);

		# Wait until ofprotocol notices that connection is broken
		sleep $wait_timer;

		# chek if the emergency table has become active
		test_emergency_cache_second($test_pkt, $options_ref, $inport, $outport);
	}
}

run_black_box_test( \&my_test, \@ARGV );
