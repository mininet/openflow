#!/usr/bin/perl -w
# test_forward_bandwidth_fixed

use strict;
use OF::Includes;

my $pkt_len   = 1512;
my $pkt_total = 1000;
my $max_idle  = 2;

sub send_expect_exact {

	my ( $ofp, $sock, $in_port, $out_port, $max_idle, $pkt_len ) = @_;
	my %delta;

	# in_port refers to the flow mod entry's input

	my $test_pkt_args = {
		DA     => "00:00:00:00:00:" . sprintf( "%02d", $out_port ),
		SA     => "00:00:00:00:00:" . sprintf( "%02d", $in_port ),
		src_ip => "192.168.200." .           ( $in_port ),
		dst_ip => "192.168.201." .           ( $out_port ),
		ttl    => 64,
		len    => $pkt_len,
		src_port => 1,
		dst_port => 0
	};
	my $test_pkt = new NF2::UDP_pkt(%$test_pkt_args);

	#print HexDump ( $test_pkt->packed );

	my $wildcards = 0x0; # exact match
	#my $wildcards = 0x2; # only wildcard the vlan
	#my $wildcards = 0x2FF; # exact match
	#my $wildcards = 0x3FE; # exact match on switch in port
	#my $wildcards = 0x3DF; # exact match on src ip
	#my $wildcards = 0x1; # exact match on eth src/dest/eth frame/ipsrcdest/128ipproto/256port source
	#my $wildcards = 0x3BF; # exact match on dest ip
	#my $wildcards = 0x3FD; # exact match on vlan
	#my $wildcards = 0x3FB; # exact match on ether source
	#my $wildcards = 0x3F7; # exact match on ether dest
	my $flags = 0x0;        # don't send flow expiry

	my $flow_mod_pkt =
	  create_flow_mod_from_udp( $ofp, $test_pkt, $in_port, $out_port,
		$max_idle, $flags, $wildcards );

	#print HexDump($flow_mod_pkt);

	# Send 'flow_mod' message
	print $sock $flow_mod_pkt;
	print "sent flow_mod message\n";

	usleep(200000);
	my @start_time = gettimeofday();
	for (my $k = 0; $k < $pkt_total; $k++) {
		send_and_count( nftest_get_iface( "eth" . ( $in_port + 1 ) ),
			$test_pkt->packed, \%delta );
		expect_and_count( nftest_get_iface( "eth" . ( $out_port + 1 ) ),
			$test_pkt->packed, \%delta );
	}
	(my $second, my $micro) = tv_interval(\@start_time);
	my $time_elapsed = ($second + $micro * 1e-6);
	my $bw_result = ($pkt_total * $pkt_len * 8) / $time_elapsed;
	print "PACKET LENGTH: $pkt_len \n";
	print "PACKETS SENT: $pkt_total\n";
	print "TIME ELAPSED: $time_elapsed \n";
	print "RESULTING BW: $bw_result bits/sec \n";

}

sub my_test {

	my ($sock, $options_ref) = @_;

	my $inport = 0;
	my $outport = 1;
	print "Checking forwarding bandwidth from $inport to $outport\n";
	send_expect_exact( $ofp, $sock, $inport, $outport, $max_idle, $pkt_len );
	wait_for_flow_expired( $ofp, $sock, $options_ref, $pkt_len, $pkt_total );
}

run_black_box_test( \&my_test );
