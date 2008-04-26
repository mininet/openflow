#!/usr/bin/perl -w
# test_forward_any_port

use strict;
use IO::Socket;
use Data::HexDump;
use Data::Dumper;

use NF2::TestLib;
use NF2::PacketLib;
use OF::OFUtil;
use OF::OFPacketLib;

sub my_test {
	
	my ($sock) = @_;
		
	my $hdr_args = {
		version => 1,
		type    => $enums{'OFPT_FLOW_MOD'},
		length  => $ofp->sizeof('ofp_flow_mod') + $ofp->sizeof('ofp_action'),
		xid     => 0x0000000
	};
	
	my $match_args = {
		wildcards => 0x3ff,    # match anything
	};
	
	my $action_output_args = {
		max_len => 0,          # send entire packet
		port    => 0
	};
	
	my $action_args = {
		type => $enums{'OFPAT_OUTPUT'},
		arg  => { output => $action_output_args }
	};
	my $action = $ofp->pack( 'ofp_action', $action_args );
	
	# not sure why either two actions are being sent or structure packing is off.
	my $flow_mod_args = {
		header    => $hdr_args,
		match     => $match_args,
		command   => $enums{'OFPFC_ADD'},
		max_idle  => 0x2,
		buffer_id => 0x0000,
		group_id  => 0
	};
	my $flow_mod = $ofp->pack( 'ofp_flow_mod', $flow_mod_args );
	
	my $pkt = $flow_mod . $action;
	
	# removed ."\0\0\0\0";
	
	print HexDump($pkt);
	
	my $pkt_len       = 64;
	my $pkt_total     = 1;
	my $test_pkt_args = {
		DA      => "00:00:00:00:00:02",
		SA      => "00:00:00:00:00:01",
		src_ip  => "0.0.0.1",
		dst_ip  => "0.0.0.2",
		ttl     => 64,
		len     => $pkt_len,
		SrcPort => 0,
		DstPort => 0
	};
	my $test_pkt = new NF2::UDP_pkt(%$test_pkt_args);
	
	# start here

	# Send 'flow_mod' message
	print $sock $pkt;
	print "sent second message\n";

	# Set up sending/receiving interfaces - NOT OpenFlow ones
	my @interfaces = ( "eth1", "eth2", "eth3", "eth4" );
	nftest_init( \@ARGV, \@interfaces, );
	nftest_start( \@interfaces, );

	# Send a packet - ensure packet comes out desired port
	nftest_send(nftest_get_iface('eth2'), $test_pkt->packed );
	nftest_expect(nftest_get_iface('eth1'), $test_pkt->packed );
	
	# Wait for flow_expired reply
	my $recvd_mesg;
	sysread( $sock, $recvd_mesg, 1512 )
	  || die "Failed to receive message: $!";

	# Inspect  message
	my $msg_size      = length($recvd_mesg);
	my $expected_size = $ofp->sizeof('ofp_flow_expired');
	compare( "msg size", length($recvd_mesg), '==', $expected_size );

	my $msg = $ofp->unpack( 'ofp_flow_expired', $recvd_mesg );

	#print HexDump ($recvd_mesg);
	print Dumper($msg);

	# Verify fields
	compare( "header version", $$msg{'header'}{'version'}, '==', 1 );
	compare( "header type", $$msg{'header'}{'type'}, '==', $enums{'OFPT_FLOW_EXPIRED'});
	compare( "header length", $$msg{'header'}{'length'}, '==', $msg_size );
	compare( "byte_count",    $$msg{'byte_count'},       '==', $pkt_len );
	compare( "packet_count",  $$msg{'packet_count'},     '==', $pkt_total );
}

run_black_box_test(\&my_test);


