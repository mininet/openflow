#!/usr/bin/perl -w
# test_unicast_known

use Test::TestLib;
use Test::PacketLib;
use OF::OFUtil;
use strict;

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
	send_and_count( nftest_get_iface('eth1'), $pkt->packed, \%delta );
	expect_and_count( nftest_get_iface('eth2'), $pkt->packed, \%delta );
	expect_and_count( nftest_get_iface('eth3'), $pkt->packed, \%delta );
	expect_and_count( nftest_get_iface('eth4'), $pkt->packed, \%delta );

	sleep 0.5;

	$pkt_args = {
		DA     => "00:00:00:00:00:01",
		SA     => "00:00:00:00:00:02",
		src_ip => "192.168.1.40",
		dst_ip => "192.168.0.40",
		ttl    => 64,
		len    => 64
	};
	$pkt = new NF2::IP_pkt(%$pkt_args);
	send_and_count( nftest_get_iface('eth2'), $pkt->packed, \%delta );
	expect_and_count( nftest_get_iface('eth1'), $pkt->packed, \%delta );
	sleep 0.5;

#	$pkt_args = {
#		DA     => "00:00:00:00:00:01",
#		SA     => "00:00:00:00:00:03",
#		src_ip => "192.168.2.40",
#		dst_ip => "192.168.0.40",
#		ttl    => 64,
#		len    => 64
#	};
#	$pkt = new NF2::IP_pkt(%$pkt_args);
#	send_and_count( nftest_get_iface('eth3'), $pkt->packed, \%delta );
#	expect_and_count( nftest_get_iface('eth1'), $pkt->packed, \%delta );
#	sleep 0.5;
#
#	$pkt_args = {
#		DA     => "00:00:00:00:00:01",
#		SA     => "00:00:00:00:00:04",
#		src_ip => "192.168.3.40",
#		dst_ip => "192.168.0.40",
#		ttl    => 64,
#		len    => 64
#	};
#	$pkt = new NF2::IP_pkt(%$pkt_args);
#	send_and_count( nftest_get_iface('eth4'), $pkt->packed, \%delta );
#	expect_and_count( nftest_get_iface('eth1'), $pkt->packed, \%delta );
#	
	return %delta;
}

# how do we pass the cmd-line arguments to the script?
run_learning_switch_test( \&my_test );
