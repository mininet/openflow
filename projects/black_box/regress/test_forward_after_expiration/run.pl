#!/usr/bin/perl -w
# test_forward_after_expiration

use strict;
use OF::Includes;

my $pkt_len   = 64;
my $pkt_total = 1;
my $max_idle  = 1;

sub send_expect_exact {

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
	usleep(100000);

	# Send a packet - ensure packet comes out desired port
	nftest_send( nftest_get_iface( "eth" . ( $in_port + 1 ) ),
		$test_pkt->packed );

	printf "sent packet on eth" . ($in_port+1) . "\n";

	nftest_expect( nftest_get_iface( "eth" . ( $out_port + 1 ) ),
		$test_pkt->packed );
	
	#wait a little while to make sure the packet gets sent along.
	#usleep(1000);

}


sub send_expect_secchan_nomatch {

	my ( $ofp, $sock, $in_port, $out_port, $max_idle, $pkt_len ) = @_;

	# in_port refers to the flow mod entry's input

	my $test_pkt_args2 = {
		DA     => "00:00:00:00:00:0" . ( $out_port + 1 ),
		SA     => "00:00:00:00:00:0" . ( $in_port + 1 ),
		src_ip => "0.0.0." .           ( $in_port + 1 ),
		dst_ip => "0.0.0." .           ( $out_port + 1 ),
		ttl    => 64,
		len    => $pkt_len,
		src_port => 1,
		dst_port => 0
	};
	my $test_pkt2 = new NF2::UDP_pkt(%$test_pkt_args2);


	print "sending out eth" . ($in_port+1) . ", expecting response on secchan due to no flow matching\n";
	# Send a packet - ensure packet comes out desired port
	nftest_send( nftest_get_iface( "eth" . ( $in_port + 1 ) ),
		$test_pkt2->packed );

	my $recvd_mesg;
	sysread($sock, $recvd_mesg, 1512) || die "Failed to receive message: $!";

	# Inspect  message
	my $msg_size = length($recvd_mesg);
	my $expected_size = $ofp->offsetof('ofp_packet_in', 'data') + length($test_pkt2->packed);
	compare ("msg size", $msg_size, '==', $expected_size);
	
	my $msg = $ofp->unpack('ofp_packet_in', $recvd_mesg);
	#print HexDump ($recvd_mesg);
	#print Dumper($msg);
	
	# Verify fields
	
	print "Verifying secchan message for packet sent in to eth" . ($in_port+1) . "\n";
	
	compare("header version", $$msg{'header'}{'version'}, '==', 1);
	compare("header type", $$msg{'header'}{'type'}, '==', $enums{'OFPT_PACKET_IN'});
	compare("header length", $$msg{'header'}{'length'}, '==', $msg_size);
	
	compare("total len", $$msg{'total_len'}, '==', length($test_pkt2->packed));
	compare("in_port", $$msg{'in_port'}, '==', $in_port);
	compare("reason", $$msg{'reason'}, '==', $enums{'OFPR_NO_MATCH'});
	
	# verify packet was unchanged!
	my $recvd_pkt_data = substr ($recvd_mesg, $ofp->offsetof('ofp_packet_in', 'data'));
	if ($recvd_pkt_data ne $test_pkt2->packed) {
	  die "ERROR: sending from eth". $in_port+1 . " received packet data didn't match packet sent\n";
	}	

}

sub my_test {

	my ($sock) = @_;

	# send from every port to every other port
	for ( my $i = 0 ; $i < 4 ; $i++ ) {
		for ( my $j = 0 ; $j < 4 ; $j++ ) {
			if ( $i != $j ) {
				print "sending from $i to $j\n";
				send_expect_exact( $ofp, $sock, $i, $j, $max_idle, $pkt_len );
				print "waiting for flow to expire\n";
				wait_for_flow_expired( $ofp, $sock, $pkt_len, $pkt_total );
				send_expect_secchan_nomatch( $ofp, $sock, $i, $j, $max_idle, $pkt_len );
			}
		}
	}
}

run_black_box_test( \&my_test );

