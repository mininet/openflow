#!/usr/bin/perl -w
# test_forward_any_port

use strict;
use OF::Includes;

my $pkt_len   = 68;
my $pkt_total = 1;
my $max_idle  = 1;

sub send_expect_exact {

	my ( $ofp, $sock, $in_port, $out_port, $max_idle, $pkt_len ) = @_;

	# in_port refers to the flow mod entry's input

	my @ipopt = ( 0x44, 0x08, 0x08, 0x00, 0x11, 0x22, 0x33, 0x44 );    #IP timestamp option
	my $test_pkt_args = {
		DA     => "00:00:00:00:00:0" . ( $out_port + 1 ),
		SA     => "00:00:00:00:00:0" . ( $in_port + 1 ),
		src_ip => "0.0.0." .           ( $in_port + 1 ),
		dst_ip => "0.0.0." .           ( $out_port + 1 ),
		ttl    => 64,
		len => $pkt_len - ( $#ipopt + 1 ),
		ip_options => \@ipopt,
		src_port   => 1,
		dst_port   => 0
	};
	my $test_pkt = new NF2::UDP_pkt(%$test_pkt_args);

	## ip_hdr_len is not correctly set by NF2 lib, so do it here.
	my $iphdr = $test_pkt->{'IP_hdr'};
	$$iphdr->ip_hdr_len( 5 + ( $#ipopt + 1 ) / 4 );    #set ip_hdr_len

	#print HexDump ( $test_pkt->packed );

	my $wildcards = 0x0;                               # exact match

	my $flow_mod_pkt =
	  create_flow_mod_from_udp( $ofp, $test_pkt, $in_port, $out_port, $max_idle, $wildcards );

	#print HexDump($flow_mod_pkt);

	# Send 'flow_mod' message
	print $sock $flow_mod_pkt;
	print "sent flow_mod message\n";
	usleep(100000);

	# Send a packet - ensure packet comes out desired port
	nftest_send( nftest_get_iface( "eth" . ( $in_port + 1 ) ), $test_pkt->packed );
	nftest_expect( nftest_get_iface( "eth" . ( $out_port + 1 ) ), $test_pkt->packed );
}

sub my_test {

	my ($sock) = @_;

	enable_flow_expirations( $ofp, $sock );

	# send from every port to every other port
	for ( my $i = 0 ; $i < 4 ; $i++ ) {
		for ( my $j = 0 ; $j < 4 ; $j++ ) {
			if ( $i != $j ) {
				print "sending from $i to $j\n";
				send_expect_exact( $ofp, $sock, $i, $j, $max_idle, $pkt_len );
				wait_for_flow_expired( $ofp, $sock, $pkt_len, $pkt_total );
			}
		}
	}
}

run_black_box_test( \&my_test );

