#!/usr/bin/perl -w
# test_delete_strict

use strict;
use IO::Socket;
use Data::HexDump;
use Data::Dumper;
use Time::HiRes qw (sleep usleep);

use NF2::TestLib;
use NF2::PacketLib;
use OF::OFUtil;
use OF::OFPacketLib;

my $pkt_len   = 64;
my $pkt_total = 1;
my $max_idle  = 1;

#my $miss_send_len = $OF::OFUtil::miss_send_len;

sub send_expect_exact_with_wildcard {

	my ( $ofp, $sock, $in_port, $out_port, $out_port2, $max_idle, $pkt_len ) = @_;

	my $test_pkt_args = {
		DA     => "00:00:00:00:00:0" . ( $out_port + 1 ),
		SA     => "00:00:00:00:00:0" . ( $in_port + 1 ),
		src_ip => "0.0.0." .           ( $in_port + 1 ),
		dst_ip => "0.0.0." .           ( $out_port + 1 ),
		ttl    => 64,
		len    => $pkt_len,
		src_port => 70,
		dst_port => 80
	};
	my $test_pkt = new NF2::UDP_pkt(%$test_pkt_args);

	my $test_pkt_args2 = {
		DA     => "00:00:00:00:00:0" . ( $out_port + 1 ),
		SA     => "00:00:00:00:00:0" . ( $in_port + 1 ),
		src_ip => "0.0.0." .           ( $in_port + 1 ),
		dst_ip => "0.0.0." .           ( $out_port + 1 ),
		ttl    => 64,
		len    => $pkt_len,
		src_port => 170,
		dst_port => 180
	};
	my $test_pkt2 = new NF2::UDP_pkt(%$test_pkt_args2);

	# Flow entry -- exact match, $out_port
	my $wildcards          = 0x0;    # exact match
	my $flow_mod_exact_pkt =
	  create_flow_mod_from_udp( $ofp, $test_pkt, $in_port, $out_port, $max_idle, $wildcards );

	# 2nd flow entry -- wildcard match, $out_port2
	$wildcards = 0x300;              # wildcad match (don't care udp src/dst ports)
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

sub delete_strict_send_expect {

	my ( $ofp, $sock, $in_port, $out_port, $out_port2, $max_idle, $pkt_len ) = @_;

	# in_port refers to the flow mod entry's input
	my $test_pkt_args = {
		DA     => "00:00:00:00:00:0" . ( $out_port + 1 ),
		SA     => "00:00:00:00:00:0" . ( $in_port + 1 ),
		src_ip => "0.0.0." .           ( $in_port + 1 ),
		dst_ip => "0.0.0." .           ( $out_port + 1 ),
		ttl    => 64,
		len    => $pkt_len,
		src_port => 70,
		dst_port => 80
	};
	my $test_pkt = new NF2::UDP_pkt(%$test_pkt_args);

	my $test_pkt_args2 = {
		DA     => "00:00:00:00:00:0" . ( $out_port + 1 ),
		SA     => "00:00:00:00:00:0" . ( $in_port + 1 ),
		src_ip => "0.0.0." .           ( $in_port + 1 ),
		dst_ip => "0.0.0." .           ( $out_port + 1 ),
		ttl    => 64,
		len    => $pkt_len,
		src_port => 170,
		dst_port => 180
	};
	my $test_pkt2 = new NF2::UDP_pkt(%$test_pkt_args2);

	my $wildcards             = 0x300;    # wildcad match (don't care udp src/dst ports)
	my $flow_mod_wildcard_pkt =
		# delete_strict_from_udp( $ofp, $test_pkt, $in_port, $out_port2, $wildcards );
 		create_flow_mod_from_udp_action( $ofp, $test_pkt, $in_port, $out_port2, $max_idle, $wildcards, 'OFPFC_DELETE_STRICT' );

	#print HexDump($flow_mod_exact_pkt);
	#print HexDump($flow_mod_wildcard_pkt);

	# Send 'flow_mod' message (delete wildcard entry with STRICT)
	print $sock $flow_mod_wildcard_pkt;
	print "sent flow_mod message (delete (strict) wildcard entry)\n";
	usleep(100000);

	# Send a packet
	print
	"Verify packets are forwarded correctly i.e., one fwded to contoller and one (exact match) fwd to the specified port\n";
	nftest_send( nftest_get_iface( "eth" . ( $in_port + 1 ) ), $test_pkt->packed );
	nftest_expect( nftest_get_iface( "eth" . ( $out_port + 1 ) ), $test_pkt->packed );

	nftest_send( nftest_get_iface( "eth" . ( $in_port + 1 ) ), $test_pkt2->packed );
	wait_for_one_packet_in( $ofp, $sock, $pkt_len, $test_pkt2->packed );
}

sub my_test {

	my ($sock) = @_;

	# send from every port to every other port
	for ( my $i = 0 ; $i < 4 ; $i++ ) {
		for ( my $j = 0 ; $j < 4 ; $j++ ) {
			if ( $i != $j ) {
				my $o_port2 = ( ( $j + 1 ) % 4 );
				print "sending from $i to $j & $i to $o_port2 -- both should match\n";
				send_expect_exact_with_wildcard( $ofp, $sock, $i, $j, $o_port2, $max_idle,
					$pkt_len );

				print "delete wildcard entry (with STRICT) \n";
				print "sending from $i to $j & $i to $o_port2 ";
				delete_strict_send_expect( $ofp, $sock, $i, $j, $o_port2, $max_idle, $pkt_len );
				wait_for_flow_expired_one( $ofp, $sock, $pkt_len, 2);
			}
		}
	}
}

run_black_box_test( \&my_test );
