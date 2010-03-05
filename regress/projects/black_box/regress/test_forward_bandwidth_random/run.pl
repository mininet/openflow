#!/usr/bin/perl -w
# test_forward_bandwidth_fixed

use strict;
use OF::Includes;

my $pkt_total = 1000;
my $max_idle  = 2;

# Maximum and minimum packet sizes
my $min_length = 64;
my $max_length = 1512;

sub send_expect_exact {

	my ( $ofp, $sock, $in_port, $out_port, $max_idle) = @_;
	my %delta;

	# in_port refers to the flow mod entry's input

	my @packets;
	my $bytes = 0;
	for (my $i = 0; $i < $pkt_total; $i++) {
		my $pkt_len = int(rand($max_length - $min_length)) + $min_length;
		$bytes += $pkt_len;
		my $test_pkt_args = {
			DA     => "00:00:00:00:00:" . sprintf( "%02d", $out_port ),
			SA     => "00:00:00:00:00:" . sprintf( "%02d", $in_port ),
			src_ip => "192.168.200." .           ( $in_port + 1 ),
			dst_ip => "192.168.201." .           ( $out_port + 1 ),
			ttl    => 64,
			len    => $pkt_len,
			src_port => 1,
			dst_port => 0
		};
		my $test_pkt = new NF2::UDP_pkt(%$test_pkt_args);
		push @packets, $test_pkt;
	}


	my $wildcards = 0x1; # wild card on input port
	my $flags = 0x0;        # don't send flow expiry

	my $test_pkt = pop @packets;
	my $flow_mod_pkt =
	  create_flow_mod_from_udp( $ofp, $test_pkt, $in_port, $out_port,
		$max_idle, $flags, $wildcards );
	push @packets, $test_pkt;

	# Send 'flow_mod' message
	print $sock $flow_mod_pkt;
	print "sent flow_mod message\n";

	usleep(200000);
	my @start_time = gettimeofday();
	for (my $k = 0; $k < $pkt_total; $k++) {
		my $packet = pop @packets;
		my $randport = int(rand(2));
		send_and_count( nftest_get_iface( "eth" . ( $randport + 1 ) ),
			$packet->packed, \%delta );
		expect_and_count( nftest_get_iface( "eth" . ( $out_port + 1 ) ),
			$packet->packed, \%delta );
	}
	(my $second, my $micro) = tv_interval(\@start_time);
	my $time_elapsed = ($second + $micro * 1e-6);
	my $bw_result = ($bytes * 8) / $time_elapsed;
	print "PACKETS SENT: $pkt_total\n";
	print "BYTES SENT: $bytes\n";
	print "TIME ELAPSED: $time_elapsed \n";
	print "RESULTING BW: $bw_result bits/sec \n";
	return $bytes;
}

sub my_test {

	my ($sock, $options_ref) = @_;

	my $inport = 0;
	my $outport = 3;
	my $bytes_sent = send_expect_exact( $ofp, $sock, $inport, $outport, $max_idle );
	wait_for_flow_expired_total_bytes( $ofp, $sock, $options_ref, $bytes_sent, $pkt_total );
}

run_black_box_test( \&my_test );
