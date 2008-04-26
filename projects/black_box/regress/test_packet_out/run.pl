#!/usr/bin/perl -w
# test_packet_out

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

	my $pkt_args = {
		DA     => "00:00:00:00:00:02",
		SA     => "00:00:00:00:00:01",
		src_ip => "192.168.0.40",
		dst_ip => "192.168.1.40",
		ttl    => 64,
		len    => 64
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

	# Send 'packet_out' message
	print $sock $pkt_sent;

	nftest_expect( nftest_get_iface('eth1'), $pkt->packed );

}

run_black_box_test( \&my_test );

