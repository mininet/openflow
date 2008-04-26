#!/usr/bin/perl -w
# test_broadcast

use NF2::TestLib;
use NF2::PacketLib;
use OF::OFUtil;
use strict;

sub my_test {

	my %delta;

	my $pkt_args = {
		DA     => "FF:FF:FF:FF:FF:FF",
		SA     => "00:00:00:00:00:01",
		src_ip => "192.168.0.40",
		dst_ip => "255.255.255.255",
		ttl    => 64,
		len    => 64
	};
	my $pkt = new NF2::IP_pkt(%$pkt_args);

	# send one broadcast packet, then do it again on the same port

	print "Sending now: \n";
	send_and_count( nftest_get_iface('eth1'), $pkt->packed, \%delta );
	expect_and_count( nftest_get_iface('eth2'), $pkt->packed, \%delta );
	expect_and_count( nftest_get_iface('eth3'), $pkt->packed, \%delta );
	expect_and_count( nftest_get_iface('eth4'), $pkt->packed, \%delta );

	# sleep as long as needed for the test to finish
	sleep 0.5;
	send_and_count( nftest_get_iface('eth1'), $pkt->packed, \%delta );
	expect_and_count( nftest_get_iface('eth2'), $pkt->packed, \%delta );
	expect_and_count( nftest_get_iface('eth3'), $pkt->packed, \%delta );
	expect_and_count( nftest_get_iface('eth4'), $pkt->packed, \%delta );
	sleep 0.5;

	# test 2:

	$pkt_args = {
		DA     => "FF:FF:FF:FF:FF:FF",
		SA     => "00:00:00:00:00:02",
		src_ip => "192.168.1.40",
		dst_ip => "255.255.255.255",
		ttl    => 64,
		len    => 64
	};
	$pkt = new NF2::IP_pkt(%$pkt_args);

	# send one broadcast packet, then do it again on the same port

	send_and_count( nftest_get_iface('eth2'), $pkt->packed, \%delta );
	expect_and_count( nftest_get_iface('eth1'), $pkt->packed, \%delta );
	expect_and_count( nftest_get_iface('eth3'), $pkt->packed, \%delta );
	expect_and_count( nftest_get_iface('eth4'), $pkt->packed, \%delta );

	# sleep as long as needed for the test to finish
	sleep 0.5;
	send_and_count( nftest_get_iface('eth2'), $pkt->packed, \%delta );
	expect_and_count( nftest_get_iface('eth1'), $pkt->packed, \%delta );
	expect_and_count( nftest_get_iface('eth3'), $pkt->packed, \%delta );
	expect_and_count( nftest_get_iface('eth4'), $pkt->packed, \%delta );
	sleep 0.5;

	# test 3:

	$pkt_args = {
		DA     => "FF:FF:FF:FF:FF:FF",
		SA     => "00:00:00:00:00:03",
		src_ip => "192.168.2.40",
		dst_ip => "255.255.255.255",
		ttl    => 64,
		len    => 64
	};
	$pkt = new NF2::IP_pkt(%$pkt_args);

	# send one broadcast packet, then do it again on the same port

	send_and_count( nftest_get_iface('eth3'), $pkt->packed, \%delta );
	expect_and_count( nftest_get_iface('eth1'), $pkt->packed, \%delta );
	expect_and_count( nftest_get_iface('eth2'), $pkt->packed, \%delta );
	expect_and_count( nftest_get_iface('eth4'), $pkt->packed, \%delta );

	# sleep as long as needed for the test to finish
	sleep 0.5;
	send_and_count( nftest_get_iface('eth3'), $pkt->packed, \%delta );
	expect_and_count( nftest_get_iface('eth1'), $pkt->packed, \%delta );
	expect_and_count( nftest_get_iface('eth2'), $pkt->packed, \%delta );
	expect_and_count( nftest_get_iface('eth4'), $pkt->packed, \%delta );
	sleep 0.5;

	# test 4:

	$pkt_args = {
		DA     => "FF:FF:FF:FF:FF:FF",
		SA     => "00:00:00:00:00:04",
		src_ip => "192.168.3.40",
		dst_ip => "255.255.255.255",
		ttl    => 64,
		len    => 64
	};
	$pkt = new NF2::IP_pkt(%$pkt_args);

	# send one broadcast packet, then do it again on the same port

	send_and_count( nftest_get_iface('eth4'), $pkt->packed, \%delta );
	expect_and_count( nftest_get_iface('eth1'), $pkt->packed, \%delta );
	expect_and_count( nftest_get_iface('eth2'), $pkt->packed, \%delta );
	expect_and_count( nftest_get_iface('eth3'), $pkt->packed, \%delta );

	# sleep as long as needed for the test to finish
	sleep 0.5;
	send_and_count( nftest_get_iface('eth4'), $pkt->packed, \%delta );
	expect_and_count( nftest_get_iface('eth1'), $pkt->packed, \%delta );
	expect_and_count( nftest_get_iface('eth2'), $pkt->packed, \%delta );
	expect_and_count( nftest_get_iface('eth3'), $pkt->packed, \%delta );

	return %delta;
}

# how do we pass the cmd-line arguments to the script?
run_learning_switch_test( \&my_test );
