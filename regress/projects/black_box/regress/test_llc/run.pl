#!/usr/bin/perl -w
# test_llc  (use $EthFMT   = "LLC")
# if you want to test DIX format, use use $EthFMT   = "DIX"

use strict;
use OF::Includes;

## choose one from "DIX" or "LLC";
#my $EthFMT   = "DIX";
my $EthFMT = "LLC";

my $pkt_len_llc = 68;
my $pkt_len_dix = 60;

my $pkt_len;
if ( $EthFMT eq "LLC" ) {
	$pkt_len = $pkt_len_llc;
	print "test for LLC\n";
}
else {
	$pkt_len = $pkt_len_dix;
	print "test for DIX\n";
}

sub send_expect_exact_oneshot {

	my ( $ofp, $sock, $in_port, $out_port, $max_idle, $pkt_len ) = @_;

	my $test_pkt_llc_ip = new NF2::PDU($pkt_len_llc);
	@{ $test_pkt_llc_ip->{'bytes'} }[ 0 .. ( $pkt_len_llc - 1 ) ] = (
		0x02, 0x02, 0x02, 0x02, 0x02, 0x02,    # dst mac 6byte (02:02:02:02:02:02)
		0x04, 0x04, 0x04, 0x04, 0x04, 0x04,    # src mac 6byte (04:04:04:04:04:04)
		0x00, 0x36,                            # 2byte (Length=54byte=0x0036)
		0xAA, 0xAA, 0x03,                      #LLC           # 3byte (always this value)
		0x00, 0x00, 0x00,                      #SNAP(OUI)     # 3byte (always this value)
		0x08, 0x00,                            #SNAP(PID)          # 2byte (0x0800 = IP)
		0x45, 0x00, 0x00, 0x2E,                # 46 byte
		0x00, 0x00, 0x40, 0x00,                #
		0x40, 0x11, 0xB8, 0x1E,                # TTL=64, proto=UDP(0x11)
		0xC0, 0xA8, 0xC9, 0x28,                # SrcIP= 192.168.201.40
		0xC0, 0xA8, 0xC8, 0x28,                # DstIP= 192.168.200.40
		0x00, 0x46, 0x00, 0x50,                # SrcPort=70, DstPort=80
		0x00, 0x1A, 0xCD, 0x3F,                # ..
		0xAE, 0xA5, 0x7F, 0x87,
		0xEE, 0x67, 0x72, 0xA7,
		0x17, 0x91, 0xFE, 0x10,
		0xBD, 0xFA, 0xC0, 0xC2,
		0x8B, 0xA7
	);

	my $test_pkt_dix_ip = new NF2::PDU($pkt_len_dix);
	@{ $test_pkt_dix_ip->{'bytes'} }[ 0 .. ( $pkt_len_dix - 1 ) ] = (
		0x02, 0x02, 0x02, 0x02, 0x02, 0x02,    # dst mac 6byte (02:02:02:02:02:02)
		0x04, 0x04, 0x04, 0x04, 0x04, 0x04,    # src mac 6byte (04:04:04:04:04:04)
		0x08, 0x00,
		0x45, 0x00, 0x00, 0x2E,                # 46 byte
		0x00, 0x00, 0x40, 0x00,                #
		0x40, 0x11, 0xB8, 0x1E,                # TTL=64, proto=UDP(0x11)
		0xC0, 0xA8, 0xC9, 0x28,                # SrcIP= 192.168.201.40
		0xC0, 0xA8, 0xC8, 0x28,                # DstIP= 192.168.200.40
		0x00, 0x46, 0x00, 0x50,                # SrcPort=70, DstPort=80
		0x00, 0x1A, 0xCD, 0x3F,                # ..
		0xAE, 0xA5, 0x7F, 0x87,
		0xEE, 0x67, 0x72, 0xA7,
		0x17, 0x91, 0xFE, 0x10,
		0xBD, 0xFA, 0xC0, 0xC2,
		0x8B, 0xA7
	);

	# Create Test Packet (only to call "create_flow_mod_from_udp")
	# which should match test_pkt_llc_ip or test_pkt_dix packet
	my $test_pkt_args = {
		DA       => "02:02:02:02:02:02",
		SA       => "04:04:04:04:04:04",
		src_ip   => "192.168.201.40",
		dst_ip   => "192.168.200.40",
		ttl      => 64,
		len      => $pkt_len,
		src_port => 70,
		dst_port => 80
	};
	my $test_pkt = new NF2::UDP_pkt(%$test_pkt_args);

	my $wildcards = 0x0;    # exact match
	my $flags = 0x0;        # don't send flow expiry
	my $flow_mod_pkt =
	  create_flow_mod_from_udp( $ofp, $test_pkt, $in_port, $out_port, $max_idle, $flags, $wildcards );

	#print HexDump($flow_mod_pkt);

	# Send 'flow_mod' message
	print $sock $flow_mod_pkt;
	print "sent flow_mod message\n";
	usleep(100000);

	# Send a packet - ensure packet comes out desired port
	if ( $EthFMT eq "LLC" ) {
		nftest_send( "eth" . ( $in_port + 1 ), $test_pkt_llc_ip->packed );
		nftest_expect( "eth" . ( $out_port + 1 ), $test_pkt_llc_ip->packed );
	}
	else {
		nftest_send( "eth" . ( $in_port + 1 ), $test_pkt_dix_ip->packed );
		nftest_expect( "eth" . ( $out_port + 1 ), $test_pkt_dix_ip->packed );
	}
}

sub my_test {

	my ($sock, $options_ref) = @_;

	my $max_idle = $$options_ref{'max_idle'};
	#my $pkt_len = $$options_ref{'pkt_len'};
	my $pkt_total = $$options_ref{'pkt_total'};

	# send from every port to every other port
	for ( my $i = 0 ; $i < 4 ; $i++ ) {
		for ( my $j = 0 ; $j < 4 ; $j++ ) {
			if ( $i != $j ) {
				print "sending from $i to $j\n";
				send_expect_exact_oneshot( $ofp, $sock, $i, $j, $max_idle, $pkt_len );
				wait_for_flow_expired( $ofp, $sock, $options_ref, $pkt_len, $pkt_total );
			}
		}
	}
}

run_black_box_test( \&my_test, \@ARGV );

