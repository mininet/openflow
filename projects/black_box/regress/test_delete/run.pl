#!/usr/bin/perl -w
# test_delete

use strict;
use OF::Includes;

my $pkt_len   = 64;
my $pkt_total = 1;
my $max_idle  = 1;

sub send_expect_exact_with_wildcard {

	my ( $ofp, $sock, $in_port, $out_port, $out_port2, $max_idle, $pkt_len ) = @_;

	my $test_pkt_args = {
		DA     => "00:00:00:00:00:0" . ( $out_port + 1 ),
		SA     => "00:00:00:00:00:0" . ( $in_port + 1 ),
		src_ip => "192.168.200." .           ( $in_port + 1 ),
		dst_ip => "192.168.201." .           ( $out_port + 1 ),
		ttl    => 64,
		len    => $pkt_len,
		src_port => 70,
		dst_port => 80
	};
	my $test_pkt = new NF2::UDP_pkt(%$test_pkt_args);

	my $test_pkt_args2 = {
		DA     => "00:00:00:00:00:0" . ( $out_port + 1 ),
		SA     => "00:00:00:00:00:0" . ( $in_port + 1 ),
		src_ip => "192.168.200." .           ( $in_port + 1 ),
		dst_ip => "192.168.201." .           ( $out_port + 1 ),
		ttl    => 64,
		len    => $pkt_len,
		src_port => 170,
		dst_port => 180
	};
	my $test_pkt2 = new NF2::UDP_pkt(%$test_pkt_args2);

	# Flow entry -- exact match, $out_port
	my $wildcards = 0x0;    # exact match
	my $flow_mod_exact_pkt =
	  create_flow_mod_from_udp( $ofp, $test_pkt, $in_port, $out_port, $max_idle, $wildcards );

	# 2nd flow entry -- wildcard match, $out_port2
	$wildcards = 0x300;     # wildcard match (don't care udp src/dst ports)
	my $flow_mod_wildcard_pkt =
	  create_flow_mod_from_udp( $ofp, $test_pkt, $in_port, $out_port2, $max_idle, $wildcards );

	#print HexDump($flow_mod_exact_pkt);
	#print HexDump($flow_mod_wildcard_pkt);

	# Send 'flow_mod' message
	print $sock $flow_mod_exact_pkt;
	print "sent flow_mod message (create exact match entry)\n";
	usleep(100000);

	print $sock $flow_mod_wildcard_pkt;
	print "sent flow_mod message (create wildcard entry)\n";
	usleep(100000);

	# Send a packet - ensure packet comes out desired port
	print "Verify packets are forwarded correctly\n";
	nftest_send( nftest_get_iface( "eth" . ( $in_port + 1 ) ), $test_pkt->packed );
	nftest_expect( nftest_get_iface( "eth" . ( $out_port + 1 ) ), $test_pkt->packed );

	nftest_send( nftest_get_iface( "eth" . ( $in_port + 1 ) ), $test_pkt2->packed );
	nftest_expect( nftest_get_iface( "eth" . ( $out_port2 + 1 ) ), $test_pkt2->packed );
}

sub delete_send_expect {

	my ( $ofp, $sock, $in_port, $out_port, $out_port2, $max_idle, $pkt_len ) = @_;

	# in_port refers to the flow mod entry's input
	my $test_pkt_args = {
		DA     => "00:00:00:00:00:0" . ( $out_port + 1 ),
		SA     => "00:00:00:00:00:0" . ( $in_port + 1 ),
		src_ip => "192.168.200." .           ( $in_port + 1 ),
		dst_ip => "192.168.201." .           ( $out_port + 1 ),
		ttl    => 64,
		len    => $pkt_len,
		src_port => 70,
		dst_port => 80
	};
	my $test_pkt = new NF2::UDP_pkt(%$test_pkt_args);

	my $test_pkt_args2 = {
		DA     => "00:00:00:00:00:0" . ( $out_port + 1 ),
		SA     => "00:00:00:00:00:0" . ( $in_port + 1 ),
		src_ip => "192.168.200." .           ( $in_port + 1 ),
		dst_ip => "192.168.201." .           ( $out_port + 1 ),
		ttl    => 64,
		len    => $pkt_len,
		src_port => 170,
		dst_port => 180
	};
	my $test_pkt2 = new NF2::UDP_pkt(%$test_pkt_args2);

	my $wildcards = 0x300;    # wildcard match (don't care udp src/dst ports)
	my $flow_mod_wildcard_pkt =
	  create_flow_mod_from_udp_action( $ofp, $test_pkt2, $in_port, $out_port2, $max_idle,
		$wildcards, "OFPFC_DELETE" );

	#print HexDump($flow_mod_exact_pkt);
	#print HexDump($flow_mod_wildcard_pkt);

	# Send 'flow_mod' message (delete wildcard entry without STRICT)
	print $sock $flow_mod_wildcard_pkt;
	print "sent flow_mod message (delete wildcard entry)\n";
	usleep(100000);

	# Send a packet
	print "Verify packets are forwarded correctly i.e., fwded to contoller\n";
	nftest_send( nftest_get_iface( "eth" . ( $in_port + 1 ) ), $test_pkt->packed );
	nftest_send( nftest_get_iface( "eth" . ( $in_port + 1 ) ), $test_pkt2->packed );

	# both pkts should go to the controller
	wait_for_one_packet_in( $ofp, $sock, $pkt_len, $test_pkt->packed );
	wait_for_one_packet_in( $ofp, $sock, $pkt_len, $test_pkt2->packed );
}

sub my_test {

	my ($sock) = @_;

	enable_flow_expirations( $ofp, $sock );

	# send from every port to every other port
	for ( my $i = 0 ; $i < 4 ; $i++ ) {
		for ( my $j = 0 ; $j < 4 ; $j++ ) {
			if ( $i != $j ) {
				my $o_port2 = ( ( $j + 1 ) % 4 );
				print "sending from $i to $j & $i to $o_port2 -- both should match\n";
				send_expect_exact_with_wildcard( $ofp, $sock, $i, $j, $o_port2, $max_idle,
					$pkt_len );

				print "delete wildcard entry (without STRICT) and send packets again\n";
				delete_send_expect( $ofp, $sock, $i, $j, $o_port2, $max_idle, $pkt_len );

			}
		}
	}
}

run_black_box_test( \&my_test );
