#!/usr/bin/perl -w
#test_fwd_delay
# send 1000 packets to find latency for both new flows and existing ones

use Test::TestLib;
use Test::PacketLib;
use OF::OFUtil;
use strict;
use Time::HiRes qw(sleep gettimeofday tv_interval usleep);

sub my_test {
	my $cnt = 0;

	my $start_time_ref = [gettimeofday];
	my %delta;
	for ( my $t = 10 ; $t < 20 ; $t++ ) {
		for ( $cnt = 10 ; $cnt < 100 ; $cnt++ ) {
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
	my $total_time_unknown = tv_interval( $start_time_ref );

	$start_time_ref = [gettimeofday()];
	for ( $cnt = 10 ; $cnt < 20 ; $cnt++ ) {
		for ( my $t = 10 ; $t < 100 ; $t++ ) {
			my $pkt_args = {
				DA     => "00:00:00:00:00:01",
				SA     => "00:00:00:00:$t:$cnt",
				src_ip => "192.168.$t.$cnt",
				dst_ip => "192.168.1.40",
				ttl    => 64,
				len    => 64
			};
			my $pkt = new NF2::IP_pkt(%$pkt_args);

			# send packet; flow entries are already added for these
			send_and_count( nftest_get_iface('eth2'), $pkt->packed, \%delta );
			expect_and_count( nftest_get_iface('eth1'), $pkt->packed, \%delta );
		}
	}
	my $total_time_known = tv_interval( $start_time_ref );
	
	# convert to ms, and consider that we sent 900 packets each
	my $time_unknown_ms = $total_time_unknown * 1000 / 900;
	my $time_known_ms = $total_time_known * 1000 / 900;
	
	printf("Delay with unknown MAC: %.3f ms\n", $time_unknown_ms);
	printf("Delay with known MAC: %.3f ms\n", $time_known_ms);

	return %delta;
}

# how do we pass the cmd-line arguments to the script?
run_learning_switch_test( \&my_test,  \@ARGV  );
