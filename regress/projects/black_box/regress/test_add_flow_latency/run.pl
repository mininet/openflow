#!/usr/bin/perl -w
# test_add_flow_latency

use strict;
use OF::Includes;

sub my_test {

	my ($sock) = @_;

	my $pkt_args = {
	    DA => "00:00:00:00:00:01",
	    SA => "00:00:00:00:00:02",
	    src_ip => "192.168.200.40",
	    dst_ip => "192.168.201.40",
	    ttl => 64,
	    len => 60
	};

	my $test_pkt = new NF2::UDP_pkt(%$pkt_args);

	my $wildcards = 0x0;
	my $in_port = 1;
	my $out_port = 2;
	my $max_idle = 0;
	my $flags = 0x0;        # don't send flow expiry

	my $flow_mod_pkt = create_flow_mod_from_udp($ofp,$test_pkt,$in_port,$out_port,$max_idle,$flags,$wildcards);

	print $sock $flow_mod_pkt;
	usleep(1000000);


	my $cnt = 0;
	my $start_time = [gettimeofday()];
	for( $cnt = 0;$cnt < 1000; $cnt++){
	    nftest_send( nftest_get_iface( "eth" . ($in_port+1)),$test_pkt->packed );
	    nftest_expect( nftest_get_iface( "eth" . ($out_port+1)),$test_pkt->packed );
	}			
	my $time_elapse = tv_interval($start_time);
	my $latency = $time_elapse*1000/1000;
	print "Latency is $latency ms";

    }


run_black_box_test( \&my_test);
