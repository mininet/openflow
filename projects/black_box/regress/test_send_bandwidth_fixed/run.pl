#!/usr/bin/perl -w
# test_send_bandwidth_fixed

use strict;
use IO::Socket;
use Data::HexDump;
use Data::Dumper;

use NF2::TestLib;
use NF2::PacketLib;
use OF::OFUtil;
use OF::OFPacketLib;

use Time::HiRes qw (sleep gettimeofday tv_interval usleep);

# Sends packets of the specified length, with specified data rate, over time = duration.
# Length is passed as a parameter and it should be also declared during packet's construction.

sub send_fixed_bandwidth_unique {
	my ( $rate, $duration, $length, $sock, $pkt, $pkt_sent, $interface ) = @_;
	my $num_packets = ( $rate * $duration ) / ( $length * 8 );
	my $inter_time  = 1000000.0 * $duration / $num_packets;

	print(
"Num Packets : $num_packets, Duration : $duration, Length : $length, InterTime : $inter_time Interface : $interface\n"
	);
	
	print "sending $num_packets packets\n";

	my @start_time = gettimeofday();  

	my $count;
	for ( $count = 0 ; $count < $num_packets ; $count++ ) {

		# Send 'packet_out' message
		print $sock $pkt_sent;
		#nftest_expect( $interface, $pkt->packed );
		usleep($inter_time);
	}
	
	my $sending_time = tv_interval(\@start_time);
	print "time elapsed: $sending_time\n";
	
	my $bps = $num_packets * $length * 8 / $sending_time;
	print "bandwidth attempted: $rate\n";
	print "bandwidth achieved: $bps\n";
}

sub my_test {

	my $pkt_args = {
		DA     => "00:00:00:00:00:02",
		SA     => "00:00:00:00:00:01",
		src_ip => "192.168.0.40",
		dst_ip => "192.168.1.40",
		ttl    => 64,
		len    => 256
	};
	my $pkt = new NF2::IP_pkt(%$pkt_args);

	my $hdr_args = {
		version => 1,
		type    => $enums{'OFPT_PACKET_OUT'},
		length  => $ofp->sizeof('ofp_packet_out') + length( $pkt->packed )
		,    # should generate automatically!
		xid => 0x0000abcd
	};
	my $packet_out_args = {
		header    => $hdr_args,
		buffer_id => -1,                    # data included in this packet
		in_port   => $enums{'OFPP_NONE'},
		out_port  => 0                      # send out eth1
	};
	my $packet_out = $ofp->pack( 'ofp_packet_out', $packet_out_args );

	my $pkt_sent = $packet_out . $pkt->packed;

	my ($sock) = @_;

	&send_fixed_bandwidth_unique( 5 * (10**6) ,
		5, 64, $sock, $pkt, $pkt_sent, 'eth1' );

	# Wait for test to finish
	sleep(1);

}

run_black_box_test( \&my_test );

