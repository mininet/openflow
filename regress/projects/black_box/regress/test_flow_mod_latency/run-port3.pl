#!/usr/bin/perl -w
# test_flow_mod_latency
#
# Don't include this test as part of the official test suite,
# as it is not supposed to pass...
#
# Run it like this :
# ./bin/of_hp_test.pl --testPath=black_box/regress/test_flow_mod_latency/run.pl
#
# Check the number of packets received :
# tcpdump -p -i eth11 -w stanford.test.log
# tcpdump -r stanford.test.log | wc
#
# On the HP, it requires increasing the SW rate limiter :
# openflow 9 sw-rate 5000
#
# Jean II

use strict;
use OF::Includes;

sub forward_flow_mod_latency {

	my ($sock, $options_ref) = @_;
	my $in_port = $$options_ref{'port_base'};
	my $out_port = $in_port + 1;
	my $fallback_port = $out_port + 1;

	my $len = $$options_ref{'pkt_len'};
	my $wildcards = 0x0;    # exact match
	my $flags = $enums{'OFPFF_SEND_FLOW_REM'};
	my $pkt_args;
	my $test_pkt;
	my $flow_mod_pkt;
	my $i;

	if (1) {
	    # Create a flow mod to track all packets sent to the controller
	    # We create a wildcard on both transport port, that sends
	    # packets to the controller - Jean II
	    $pkt_args = {
		DA     => "00:00:00:00:00:" . sprintf( "%02d", $out_port ),
		SA     => "00:00:00:00:00:" . sprintf( "%02d", $in_port ),
		src_ip => "192.168.200." .     ( $in_port ),
		dst_ip => "192.168.201." .     ( $out_port ),
		ttl    => 64,
		len    => $len,
		src_port => 0,
		dst_port => 0
	    };
	    $test_pkt = new NF2::UDP_pkt(%$pkt_args);
	    $wildcards =  $enums{'OFPFW_TP_SRC'} | $enums{'OFPFW_TP_DST'};
	    print"wildcards = $wildcards\n";
	    # Full experiment is around 15s
	    $flow_mod_pkt = create_flow_mod_from_udp( $ofp, $test_pkt, $in_port, $fallback_port, 25, $flags, $wildcards );
	    syswrite( $sock, $flow_mod_pkt );
	    print "sent flow_mod message with wildcard\n";

	    # Make sure the flow mod is properly inserted and the 
	    # OpenFlow instance properly started. The OpenFlow instance
	    # takes time to get started, we want to make sure this is
	    # not a factor. Jean II
	    sleep(1);

	    # No more wildcards
	    $wildcards = 0x0;    # exact match
	}

	# Let's create 100 sequencial connections - Jean II
	for ( my $c = 0 ; $c < 100 ; $c++ ) {

	    # Packets for creating the flow mod
	    $pkt_args = {
		DA     => "00:00:00:00:00:" . sprintf( "%02d", $out_port ),
		SA     => "00:00:00:00:00:" . sprintf( "%02d", $in_port ),
		src_ip => "192.168.200." .     ( $in_port ),
		dst_ip => "192.168.201." .     ( $out_port ),
		ttl    => 64,
		len    => $len,
		src_port => 2000 + $c,
		dst_port => 4000 + $c
	    };
	    $test_pkt = new NF2::UDP_pkt(%$pkt_args);

	    # Let's create a long lived flow mod
	    $flow_mod_pkt = create_flow_mod_from_udp( $ofp, $test_pkt, $in_port, $out_port, 20, $flags, $wildcards );

	    # Send 'flow_mod' message
	    syswrite( $sock, $flow_mod_pkt );
	    print "sent flow_mod message for connection $c\n";

	    # Test packet to be sent - should match flow mod
	    $pkt_args = {
		DA     => "00:00:00:00:00:" . sprintf( "%02d", $out_port ),
		SA     => "00:00:00:00:00:" . sprintf( "%02d", $in_port ),
		src_ip => "192.168.200." .     ( $in_port ),
		dst_ip => "192.168.201." .     ( $out_port ),
		ttl    => 64,
		len    => $len,
		src_port => 2000 + $c,
		dst_port => 4000 + $c
	    };
	    $test_pkt = new NF2::UDP_pkt(%$pkt_args);

	    # For this test, the TCAM is much slower. Wait a bit more
	    # to get more interesting results. I also increased pkt count.
	    # Jean II
	    usleep(20000);

	    # Max in SW is around 5000 pkts/sec
	    # Note : default rate limiter value is 100 pkts/sec, which is
	    # one packet every 10s, so you can't run at default value
	    # Send 15 packets as a short burst over 60ms
	    for ($i = 0 ; $i < 15 ; $i++ ) {

		# Wait 4 ms between packets
		usleep(4000);

		# Send test packet
		nftest_send( "eth" . ($in_port), $test_pkt->packed );

		# This does not block, so we are good...
		nftest_expect( "eth" . ($out_port), $test_pkt->packed );
	    }

	    # We don't wait for flow expiry, that's too long waiting - Jean II
	}

	# Wait for stats to refresh
	# For most flow mod, we should be about half life, which means
	# they have not expired yet, and have already got stats a few time.
	sleep(6);
	dpctl_show_flows($options_ref);
}

run_black_box_test( \&forward_flow_mod_latency, \@ARGV );
