#!/usr/bin/perl -w
# test_ip_protocol (udp)

use strict;
use OF::Includes;

sub send_expect_exact {

	my ( $ofp, $sock, $in_port, $out_port, $max_idle, $pkt_len ) = @_;

	# in_port refers to the flow mod entry's input

	my $test_pkt_args = {
		DA     => "00:00:00:00:00:" . sprintf( "%02d", $out_port ),
		SA     => "00:00:00:00:00:" . sprintf( "%02d", $in_port ),
		src_ip => "192.168.200." .           ( $in_port ),
		dst_ip => "192.168.201." .           ( $out_port ),
		ttl    => 64,
		len    => $pkt_len,
		src_port => 70,
		dst_port => 80
	};
	my $test_pkt = new NF2::UDP_pkt(%$test_pkt_args);

	#print HexDump ( $test_pkt->packed );

	my $wildcards = 0x0;    # exact match
	my $flags = 0x0;        # don't send flow expiry

	my $flow_mod_pkt =
	  create_flow_mod_from_udp( $ofp, $test_pkt, $in_port, $out_port,
		  $max_idle, $flags, $wildcards );

	#print HexDump($flow_mod_pkt);

	# Send 'flow_mod' message
	print $sock $flow_mod_pkt;
	print "sent flow_mod message\n";
	usleep(100000);

	# Send a packet - ensure packet comes out desired port
	nftest_send( "eth" . ( $in_port + 1 ), $test_pkt->packed );
	nftest_expect( "eth" . ( $out_port + 1 ), $test_pkt->packed );
}

sub my_test {

	my ($sock, $options_ref) = @_;

	my $max_idle = $$options_ref{'max_idle'};
	my $pkt_len = $$options_ref{'pkt_len'};
	my $pkt_total = $$options_ref{'pkt_total'};

	# send from every port to every other port
	for ( my $i = 0 ; $i < 4 ; $i++ ) {
		for ( my $j = 0 ; $j < 4 ; $j++ ) {
			if ( $i != $j ) {
				print "sending from $i to $j\n";
				send_expect_exact( $ofp, $sock, $i, $j, $max_idle, $pkt_len );
				wait_for_flow_expired_all( $ofp, $sock, $options_ref );
			}
		}
	}
}

run_black_box_test( \&my_test, \@ARGV );

