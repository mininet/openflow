#!/usr/bin/perl -w
# test_forward_exact_all

use strict;
use IO::Socket;
use Data::HexDump;
use Data::Dumper;

use NF2::TestLib;
use NF2::PacketLib;
use OF::OFUtil;
use OF::OFPacketLib;

my $pkt_len   = 64;
my $pkt_total = 1;
my $max_idle  = 1;

sub send_expect_multiple {

	my ( $ofp, $sock, $in_port, $out_port, $max_idle, $pkt_len ) = @_;

	# in_port refers to the flow mod entry's input

	my $test_pkt_args = {
		DA     => "00:00:00:00:00:0" . ( $out_port + 1 ),
		SA     => "00:00:00:00:00:0" . ( $in_port + 1 ),
		src_ip => "0.0.0." .           ( $in_port + 1 ),
		dst_ip => "0.0.0." .           ( $out_port + 1 ),
		ttl    => 64,
		len    => $pkt_len,
		src_port => 1,
		dst_port => 0
	};
	my $test_pkt = new NF2::UDP_pkt(%$test_pkt_args);

	#print HexDump ( $test_pkt->packed );

	my $wildcards = 0x0; # exact match

	my $flow_mod_pkt =
	  create_flow_mod_from_udp( $ofp, $test_pkt, $in_port, $out_port,
		$max_idle, $wildcards );

	#print HexDump($flow_mod_pkt);

	# Send 'flow_mod' message
	print $sock $flow_mod_pkt;
	print "sent flow_mod message\n";

	# Send a packet - ensure packet comes out desired port
	nftest_send( nftest_get_iface( "eth" . ( $in_port + 1 ) ),
		$test_pkt->packed );

	for(my $k = 0; $k < 4; $k++)
	  {
	    if($k+1 != $in_port+1)
	      {
		nftest_expect( nftest_get_iface( "eth" . ( $k + 1 ) ),
			       $test_pkt->packed );
	      }
	  }

}

sub my_test {

	my ($sock) = @_;
	my $j = 0xfffb;
	#all ports except the incoming port
	#NOTE: 0xfffc appears to NOT work.

	# send from every port, receive on every port except the send port
	for ( my $i = 0 ; $i < 4 ; $i++ ) {
	  print "sending from $i to (all ports but $i)\n";
	  send_expect_multiple( $ofp, $sock, $i, $j, $max_idle, $pkt_len );
	  wait_for_flow_expired( $ofp, $sock, $pkt_len, $pkt_total );
	}
}

run_black_box_test( \&my_test );

