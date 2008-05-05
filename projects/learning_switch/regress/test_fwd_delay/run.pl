#!/usr/bin/perl -w
#test_unicast_unknown

use NF2::TestLib;
use NF2::PacketLib;
use OF::OFUtil;
use strict;
use Time::HiRes qw(sleep gettimeofday tv_interval usleep);

sub my_test {
	my $cnt = 0;

	my @start_time = gettimeofday();
	my %delta;
    for (my $t = 10; $t < 20; $t ++){
     for ($cnt = 10; $cnt < 100; $cnt ++){
	my $pkt_args = {
		DA     => "00:01:00:00:$t:$cnt",
		SA     => "00:00:00:00:00:01",
		src_ip => "192.168.0.40",
		dst_ip => "192.168.$cnt.$t",
		ttl    => 64,
		len    => 64
	};
	my $pkt = new NF2::IP_pkt(%$pkt_args);

	
	# send one packet; controller should learn MAC, add a flow
	#  entry, and send this packet out the other interfaces

	send_and_count( nftest_get_iface('eth1'), $pkt->packed, \%delta );
	expect_and_count( nftest_get_iface('eth2'), $pkt->packed, \%delta );
	expect_and_count( nftest_get_iface('eth3'), $pkt->packed, \%delta );
	expect_and_count( nftest_get_iface('eth4'), $pkt->packed, \%delta );
}
}
	my @load_time1 = tv_interval(\@start_time);


	my @start_time = gettimeofday();
     for ($cnt = 10; $cnt < 20; $cnt ++){
     for (my $t = 10; $t < 100; $t ++){
	my $pkt_args = {
		DA     => "00:00:00:00:00:01",
		SA     => "00:00:00:00:$t:$cnt",
		src_ip => "192.168.$t.$cnt",
		dst_ip => "192.168.1.40",
		ttl    => 64,
		len    => 64
	};
	my $pkt = new NF2::IP_pkt(%$pkt_args);

	send_and_count( nftest_get_iface('eth2'), $pkt->packed, \%delta );
	expect_and_count( nftest_get_iface('eth1'), $pkt->packed, \%delta );
}
}
	my @load_time = tv_interval(\@start_time);
	print "Dealy with unknown MAC for 1000 pkts: @load_time1\n";
	print "Dealy with known MAC for 1000 pkts: @load_time\n";

	return %delta;
}

# how do we pass the cmd-line arguments to the script?
run_learning_switch_test( \&my_test );
