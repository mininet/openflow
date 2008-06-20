#!/usr/bin/perl -w
# test_send_bandwidth_fixed

use strict;
use OF::Includes;

use Time::HiRes qw (sleep gettimeofday tv_interval usleep);

# Sends packets of the specified length, with specified data rate, over time = duration.
# A random interarrival time between packets is used, trying to fit the requested data rate.

sub send_random_bandwidth_unique {
	my ( $rate, $duration, $sock, $pkt, $pkt_sent, $interface ) = @_;
	my $length = length( $pkt->packed );
	my $num_packets = ( $rate * $duration ) / ( $length * 8 );
	my $inter_time  = 1000000.0 * $duration / $num_packets;
	
	print "Running Test for a single packet size\n";
	print(
"Num Packets : $num_packets, Duration : $duration, Length : $length, InterTime : $inter_time Interface : $interface\n"
	);
	
	print "sending $num_packets packets\n";

	my @start_time = gettimeofday();  
	my $sending_time = tv_interval(\@start_time);

	my $count = 0;
	while($sending_time < $duration){
	    # Send 'packet_out' message
	    print $sock $pkt_sent;
	    nftest_expect( $interface, $pkt->packed );
	    usleep(int(rand(2*$inter_time)));
	    $count++;
	    $sending_time = tv_interval(\@start_time);
	}
	print "time elapsed: $sending_time (loops : $count) \n";
	
	my $bps = $count * $length * 8 / $sending_time;
	print "bandwidth attempted: $rate (bps)\n";
	print "bandwidth achieved:  $bps  (bps)\n";
}

sub send_random_bandwidth_mixed {
	my ( $rate, $duration, $sock, $pkt_sent_small,$pkt_sent_med,$pkt_sent_lrg,$pkt_small,$pkt_med,$pkt_lrg, $interface ) = @_;
	my $len_s = length($pkt_small->packed);
	my $len_m = length($pkt_med->packed);
	my $len_l = length($pkt_lrg->packed);
	my $num_loops = ( $rate * $duration ) / (( $len_s+$len_m+$len_l ) * 8 );
	my $num_packets = $num_loops*3;
	my $inter_time  = 1000000.0 * $duration / $num_packets;

	print "Running Test for different packet sizes\n";
	print(
"Num Packets : $num_packets, Duration : $duration, Lengths : $len_s,$len_m,$len_l, InterTime : $inter_time Interface : $interface\n"
	);
	
	print "sending $num_packets packets\n";

	my @start_time = gettimeofday();  
	my $sending_time = tv_interval(\@start_time);

	my $count = 0;
	while ($sending_time < $duration){
	    # Send 'packet_out' message
	    print $sock $pkt_sent_small;		
	    nftest_expect( $interface, $pkt_small->packed );
	    usleep(int(rand(2*$inter_time)));		
	    print $sock $pkt_sent_med;
	    nftest_expect( $interface, $pkt_med->packed );
	    usleep(int(rand(2*$inter_time)));		
	    print $sock $pkt_sent_lrg;						
	    nftest_expect( $interface, $pkt_lrg->packed );
	    usleep(int(rand(2*$inter_time)));		
	    $count++;
	    $sending_time = tv_interval(\@start_time);
	}
	
	print "time elapsed: $sending_time (loops : $count)\n";
	
	my $bps = $count * ($len_s+$len_m+$len_l) * 8 / $sending_time;
	print "bandwidth attempted: $rate(bps)\n";
	print "bandwidth achieved:  $bps (bps)\n";
}



sub my_test {

	my $pkt_args = {
		DA     => "00:00:00:00:00:02",
		SA     => "00:00:00:00:00:01",
		src_ip => "192.168.200.40",
		dst_ip => "192.168.201.40",
		ttl    => 64,
		len    => 64
	};
	my $pkt_small = new NF2::IP_pkt(%$pkt_args);
	$pkt_args->{ 'len' } = 256;
	my $pkt_med = new NF2::IP_pkt(%$pkt_args);
	$pkt_args->{ 'len' } = 512;
	my $pkt_lrg = new NF2::IP_pkt(%$pkt_args);

	my $hdr_args = {
		version => 1,
		type    => $enums{'OFPT_PACKET_OUT'},
		length  => $ofp->sizeof('ofp_packet_out') + length( $pkt_small->packed ),    # should generate automatically!
		xid => 0x0000abcd
	};
	my $packet_out_args = {
		header    => $hdr_args,
		buffer_id => -1,                    # data included in this packet
		in_port   => $enums{'OFPP_NONE'},
		out_port  => 0                      # send out eth1
	};
	my $packet_out = $ofp->pack( 'ofp_packet_out', $packet_out_args );

	my $pkt_sent_small = $packet_out . $pkt_small->packed;
	$hdr_args->{'length'} = $ofp->sizeof('ofp_packet_out') + length( $pkt_med->packed );
	$packet_out_args->{'header'} = $hdr_args;
	$packet_out = $ofp->pack( 'ofp_packet_out', $packet_out_args );
	my $pkt_sent_med = $packet_out . $pkt_med->packed;
	$hdr_args->{'length'} = $ofp->sizeof('ofp_packet_out') + length( $pkt_lrg->packed );
	$packet_out_args->{'header'} = $hdr_args;
	$packet_out = $ofp->pack( 'ofp_packet_out', $packet_out_args );
	my $pkt_sent_lrg = $packet_out . $pkt_lrg->packed;

	my ($sock) = @_;


	&send_random_bandwidth_unique( .01 * (10**6) ,15, $sock, $pkt_lrg, $pkt_sent_lrg, 'eth1' );

	#&send_random_bandwidth_mixed( 5 * (10**5) ,5, $sock,$pkt_sent_small,$pkt_sent_med, $pkt_sent_lrg,$pkt_small,$pkt_med,$pkt_lrg,'eth1');

	# Wait for test to finish
	sleep(2);

}

run_black_box_test( \&my_test );

