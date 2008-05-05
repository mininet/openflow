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
my $max_idle  = 4;

my $miss_send_len = $OF::OFUtil::miss_send_len;

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
	  delete_strict_from_udp( $ofp, $test_pkt, $in_port, $out_port2, $wildcards );

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
}

sub wait_for_flow_expired_one {

	my ( $ofp, $sock, $pkt_len, $pkt_total ) = @_;

	my $recvd_mesg;
	sysread( $sock, $recvd_mesg, $ofp->sizeof('ofp_flow_expired') )
	  || die "Failed to receive message: $!";

	#print HexDump ($recvd_mesg);

	# Inspect  message
	my $msg_size      = length($recvd_mesg);
	my $expected_size = $ofp->sizeof('ofp_flow_expired');
	compare( "msg size", length($recvd_mesg), '==', $expected_size );

	my $msg = $ofp->unpack( 'ofp_flow_expired', $recvd_mesg );

	#print Dumper($msg);

	# Verify fields
	compare( "header version", $$msg{'header'}{'version'}, '==', 1 );
	compare( "header type",    $$msg{'header'}{'type'},    '==', $enums{'OFPT_FLOW_EXPIRED'} );
	compare( "header length",  $$msg{'header'}{'length'},  '==', $msg_size );
	compare( "byte_count",     $$msg{'byte_count'},        '==', $pkt_len * $pkt_total );
	compare( "packet_count",   $$msg{'packet_count'},      '==', $pkt_total );
}

sub wait_for_packet_in {
	my ( $ofp, $sock, $pkt_len ) = @_;

	my $pkt_in_msg_size;
	if ( $pkt_len < $miss_send_len ) {    # assuming "miss_send_len" in hello is 128 bytes
		$pkt_in_msg_size = 18 + $pkt_len;
	}
	else {
		$pkt_in_msg_size = 18 + $miss_send_len;
	}

	my $recvd_mesg;
	sysread( $sock, $recvd_mesg, $pkt_in_msg_size )
	  || die "Failed to receive message: $!";

	#print HexDump ($recvd_mesg);

	# Inspect  message
	my $msg_size      = length($recvd_mesg);
	my $expected_size = $pkt_in_msg_size;
	compare( "msg size", length($recvd_mesg), '==', $expected_size );

	my $msg = $ofp->unpack( 'ofp_packet_in', $recvd_mesg );

	#print Dumper($msg);

	# Verify fields
	compare( "header version", $$msg{'header'}{'version'}, '==', 1 );
	compare( "header type",    $$msg{'header'}{'type'},    '==', $enums{'OFPT_PACKET_IN'} );
	compare( "header length",  $$msg{'header'}{'length'},  '==', $msg_size );
	compare( "header length",  $$msg{'total_len'},         '==', $pkt_len );

	print "pkt (length = $pkt_len) is received by the controller\n";
}

sub delete_strict_from_udp {

	my ( $ofp, $udp_pkt, $in_port, $out_port, $wildcards ) = @_;

	my $hdr_args = {
		version => 1,
		type    => $enums{'OFPT_FLOW_MOD'},
		length  => $ofp->sizeof('ofp_flow_mod') + $ofp->sizeof('ofp_action'),
		xid     => 0x0000000
	};

	# might be cleaner to convert the exported colon-hex MAC addrs
	#print ${$udp_pkt->{Ethernet_hdr}}->SA . "\n";
	#print ${$test_pkt->{Ethernet_hdr}}->SA . "\n";
	my $ref_to_eth_hdr = ( $udp_pkt->{'Ethernet_hdr'} );
	my $ref_to_ip_hdr  = ( $udp_pkt->{'IP_hdr'} );

	# pointer to array
	my $eth_hdr_bytes    = $$ref_to_eth_hdr->{'bytes'};
	my $ip_hdr_bytes     = $$ref_to_ip_hdr->{'bytes'};
	my @dst_mac_subarray = @{$eth_hdr_bytes}[ 0 .. 5 ];
	my @src_mac_subarray = @{$eth_hdr_bytes}[ 6 .. 11 ];

	my @src_ip_subarray = @{$ip_hdr_bytes}[ 12 .. 15 ];
	my @dst_ip_subarray = @{$ip_hdr_bytes}[ 16 .. 19 ];

	my $src_ip =
	  ( ( 2**24 ) * $src_ip_subarray[0] + ( 2**16 ) * $src_ip_subarray[1] + ( 2**8 ) *
		  $src_ip_subarray[2] + $src_ip_subarray[3] );

	my $dst_ip =
	  ( ( 2**24 ) * $dst_ip_subarray[0] + ( 2**16 ) * $dst_ip_subarray[1] + ( 2**8 ) *
		  $dst_ip_subarray[2] + $dst_ip_subarray[3] );

	my $match_args = {
		wildcards => $wildcards,
		in_port   => $in_port,
		dl_src    => \@src_mac_subarray,
		dl_dst    => \@dst_mac_subarray,
		dl_vlan   => 0xffff,
		dl_type   => 0x0800,
		nw_src    => $src_ip,
		nw_dst    => $dst_ip,
		nw_proto  => 17,                                  #udp
		tp_src    => ${ $udp_pkt->{UDP_pdu} }->SrcPort,
		tp_dst    => ${ $udp_pkt->{UDP_pdu} }->DstPort
	};
	my $action_output_args = {
		max_len => 0,                                     # send entire packet
		port    => $out_port
	};

	my $action_args = {
		type => $enums{'OFPAT_OUTPUT'},
		arg  => { output => $action_output_args }
	};
	my $action = $ofp->pack( 'ofp_action', $action_args );

	my $flow_mod_args = {
		header    => $hdr_args,
		match     => $match_args,
		command   => $enums{'OFPFC_DELETE_STRICT'},
		buffer_id => 0x0000,
		group_id  => 0
	};
	my $flow_mod = $ofp->pack( 'ofp_flow_mod', $flow_mod_args );

	my $flow_mod_pkt = $flow_mod . $action;

	return $flow_mod_pkt;
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

				#				wait_for_flow_expired_one( $ofp, $sock, $pkt_len, $pkt_total );
				#				wait_for_flow_expired_one( $ofp, $sock, $pkt_len, $pkt_total );
				print "delete wildcard entry (with STRICT) \n";
				print "sending from $i to $j & $i to $o_port2 ";
				delete_strict_send_expect( $ofp, $sock, $i, $j, $o_port2, $max_idle, $pkt_len );
				wait_for_packet_in( $ofp, $sock, $pkt_len );
				wait_for_flow_expired_one( $ofp, $sock, $pkt_len, 2 );

			}
		}
	}
}

run_black_box_test( \&my_test );
