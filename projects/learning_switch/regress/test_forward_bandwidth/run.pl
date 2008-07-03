#!/usr/bin/perl -w
#test_unicast_unknown

use Test::TestLib;
use Test::PacketLib;
use OF::OFUtil;
use Time::HiRes qw(sleep gettimeofday tv_interval usleep);
use strict;

sub my_test {
	my $cnt = 0;
	my %delta;
	my $pkt_len = 1512;

	my $pkt_args = {
		DA     => "00:01:00:00:00:02",
		SA     => "00:00:00:00:00:01",
		src_ip => "192.168.0.40",
		dst_ip => "192.168.0.41",
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

	my @start_time = gettimeofday();
	for ( $cnt = 10 ; $cnt < 20 ; $cnt++ ) {
		for ( my $t = 10 ; $t < 100 ; $t++ ) {
			my $pkt_args = {
				DA     => "00:00:00:00:00:01", 
				SA     => "00:00:00:00:$t:$cnt",
				src_ip => "192.168.$t.$cnt",
				dst_ip => "192.168.1.40",
				ttl    => 64,
				len    => $pkt_len
			};
			my $pkt = new NF2::IP_pkt(%$pkt_args);

			send_and_count( nftest_get_iface('eth2'), $pkt->packed, \%delta );
			expect_and_count( nftest_get_iface('eth1'), $pkt->packed, \%delta );
		}
	}
	( my $second, my $micro ) = tv_interval( \@start_time );
	my $time_elapsed = ( $second + $micro * 1e-6 );

	my $bw_result = (900 * $pkt_len * 8) / $time_elapsed;
	print "PACKET LENGTH: $pkt_len \n";
	print "TIME ELAPSED: $time_elapsed \n";
	print "RESULTING BW: $bw_result bits/sec \n";

	return %delta;
}

# how do we pass the cmd-line arguments to the script?
run_learning_switch_test( \&my_test, \@ARGV  );
