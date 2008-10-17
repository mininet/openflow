#!/usr/bin/perl -w
# test_unicast_multiple_hosts

use strict;
use OF::Includes;

sub my_test {

	my %delta;

	my $pkt_args = {
		DA     => "00:00:00:00:00:02",
		SA     => "00:00:00:00:00:01",
		src_ip => "192.168.0.40",
		dst_ip => "192.168.1.40",
		ttl    => 64,
		len    => 64
	};
	my $pkt = new NF2::IP_pkt(%$pkt_args);

	# send one packet; controller should learn MAC, add a flow
	#  entry, and send this packet out the other interfaces
	print "Sending now: \n";
	send_and_count( 'eth1', $pkt->packed, \%delta );
	expect_and_count( 'eth2', $pkt->packed, \%delta );
	expect_and_count( 'eth3', $pkt->packed, \%delta );
	expect_and_count( 'eth4', $pkt->packed, \%delta );

	# sleep as long as needed for the test to finish
	sleep 0.5;
	my $count = 10;
	my $cnt   = 10;

	for ( $cnt = 11 ; $cnt < 21 ; $cnt++ ) {
		for ( $count = 10 ; $count < 12 ; $count++ ) {

			$pkt_args = {
				DA     => "00:00:00:00:00:01",
				SA     => "00:00:00:$cnt:10:$count",
				src_ip => "192.168.$count.$cnt",
				dst_ip => "192.168.0.40",
				ttl    => 64,
				len    => 64
			};
			$pkt = new NF2::IP_pkt(%$pkt_args);
			send_and_count( 'eth2', $pkt->packed, \%delta );
			expect_and_count( 'eth1', $pkt->packed, \%delta );
			sleep 0.1;

		}
	}

	for ( $cnt = 21 ; $cnt < 31 ; $cnt++ ) {
		for ( $count = 10 ; $count < 12 ; $count++ ) {

			$pkt_args = {
				DA     => "00:00:00:00:00:01",
				SA     => "00:00:00:$cnt:11:$count",
				src_ip => "192.168.$count.$cnt",
				dst_ip => "192.168.0.40",
				ttl    => 64,
				len    => 64
			};
			$pkt = new NF2::IP_pkt(%$pkt_args);
			send_and_count( 'eth3', $pkt->packed, \%delta );
			expect_and_count( 'eth1', $pkt->packed, \%delta );
			sleep 0.1;
		}
	}

	for ( $cnt = 31 ; $cnt < 41 ; $cnt++ ) {
		for ( $count = 10 ; $count < 12 ; $count++ ) {

			$pkt_args = {
				DA     => "00:00:00:00:00:01",
				SA     => "00:00:00:$cnt:12:$count",
				src_ip => "192.168.$count.$cnt",
				dst_ip => "192.168.0.40",
				ttl    => 64,
				len    => 64
			};
			$pkt = new NF2::IP_pkt(%$pkt_args);
			send_and_count( 'eth4', $pkt->packed, \%delta );
			expect_and_count( 'eth1', $pkt->packed, \%delta );
			sleep 0.1;

		}
	}

	return %delta;
}

run_learning_switch_test( \&my_test,  \@ARGV  );