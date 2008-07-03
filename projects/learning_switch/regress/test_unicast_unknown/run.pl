#!/usr/bin/perl -w
#test_unicast_unknown

use strict;
use OF::Includes;

sub my_test {

	my $pkt_args = {
		DA     => "00:00:00:00:00:02",
		SA     => "00:00:00:00:00:01",
		src_ip => "192.168.0.40",
		dst_ip => "192.168.1.40",
		ttl    => 64,
		len    => 64
	};
	my $pkt = new NF2::IP_pkt(%$pkt_args);

	my %delta;
	
	# send one packet; controller should learn MAC, add a flow
	#  entry, and send this packet out the other interfaces
	print "Sending now: \n";
	send_and_count( 'eth1', $pkt->packed, \%delta );
	expect_and_count( 'eth2', $pkt->packed, \%delta );
	expect_and_count( 'eth3', $pkt->packed, \%delta );
	expect_and_count( 'eth4', $pkt->packed, \%delta );

	return %delta;
}

run_learning_switch_test( \&my_test,  \@ARGV  );
