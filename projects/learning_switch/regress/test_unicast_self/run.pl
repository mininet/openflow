#!/usr/bin/perl -w
# test_unicast_self

use strict;
use OF::Includes;

sub my_test {

	my %delta;

	# Send packets with same DA and SA; should be ignored
	my $pkt_args = {
		DA     => "00:00:00:00:00:01",
		SA     => "00:00:00:00:00:01",
		src_ip => "192.168.0.40",
		dst_ip => "192.168.0.40",
		ttl    => 64,
		len    => 64
	};
	my $pkt = new NF2::IP_pkt(%$pkt_args);

	print "Sending now: \n";
	send_and_count( 'eth1', $pkt->packed, \%delta );

	$pkt_args = {
		DA     => "00:00:00:00:00:02",
		SA     => "00:00:00:00:00:02",
		src_ip => "192.168.1.40",
		dst_ip => "192.168.1.40",
		ttl    => 64,
		len    => 64
	};
	$pkt = new NF2::IP_pkt(%$pkt_args);
	send_and_count( 'eth2', $pkt->packed, \%delta );

	$pkt_args = {
		DA     => "00:00:00:00:00:03",
		SA     => "00:00:00:00:00:03",
		src_ip => "192.168.2.40",
		dst_ip => "192.168.2.40",
		ttl    => 64,
		len    => 64 
	};
	$pkt = new NF2::IP_pkt(%$pkt_args);
	send_and_count( 'eth3', $pkt->packed, \%delta );

	$pkt_args = {
		DA     => "00:00:00:00:00:04",
		SA     => "00:00:00:00:00:04",
		src_ip => "192.168.3.40",
		dst_ip => "192.168.3.40",
		ttl    => 64,
		len    => 64
	};
	$pkt = new NF2::IP_pkt(%$pkt_args);
	send_and_count( 'eth4', $pkt->packed, \%delta );

	return %delta;
}

run_learning_switch_test( \&my_test,  \@ARGV  );
