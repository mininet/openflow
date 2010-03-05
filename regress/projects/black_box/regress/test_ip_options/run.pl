#!/usr/bin/perl -w
# test_ip_options

use strict;
use OF::Includes;

sub send_expect_exact {

	my ( $ofp, $sock, $options_ref, $in_port_offset, $out_port_offset, $max_idle, $pkt_len ) = @_;

	my $in_port = $in_port_offset + $$options_ref{'port_base'};
	my $out_port = $out_port_offset + $$options_ref{'port_base'};		

	# in_port refers to the flow mod entry's input
	my @ipopt = ( 0x44, 0x08, 0x08, 0x00, 0x11, 0x22, 0x33, 0x44 );    #IP timestamp option
	my $num_ipopt = @ipopt;

	my $test_pkt_args = {
		DA     => "00:00:00:00:00:" . sprintf( "%02d", $out_port ),
		SA     => "00:00:00:00:00:" . sprintf( "%02d", $in_port ),
		src_ip => "192.168.200." .           ( $in_port ),
		dst_ip => "192.168.201." .           ( $out_port ),
		ttl    => 64,
		len => $pkt_len,
		ip_hdr_len =>  5 + ( $#ipopt + 1 ) / 4,
		ip_options => \@ipopt,
		src_port   => 1,
		dst_port   => 0

	};
	my $test_pkt = new NF2::UDP_pkt(%$test_pkt_args);

	#print ("pkt_len = $pkt_len\n");
	#print HexDump ( $test_pkt->packed );

	my $wildcards = 0x0;                               # exact match
	my $flags = $enums{'OFPFF_SEND_FLOW_REM'};

	my $flow_mod_pkt =
	  create_flow_mod_from_udp( $ofp, $test_pkt, $in_port, $out_port, $max_idle, $flags, $wildcards );
	#print HexDump($flow_mod_pkt);

	# Send 'flow_mod' message
	print $sock $flow_mod_pkt;
	print "sent flow_mod message\n";
	
	# Give OF switch time to process the flow mod
	usleep($$options_ref{'send_delay'});

	# Send a packet - ensure packet comes out desired port
	nftest_send("eth" . ( $in_port_offset + 1 ), $test_pkt->packed );
	nftest_expect( "eth" . ( $out_port_offset + 1 ), $test_pkt->packed );
}

sub test_ip_options {

	my ( $ofp, $sock, $options_ref, $i, $j, $wildcards ) = @_;

	my $max_idle =  $$options_ref{'max_idle'};
	#my $pkt_len = $$options_ref{'pkt_len'};
	my $pkt_len   = 68;
	my $pkt_total = $$options_ref{'pkt_total'};

	send_expect_exact( $ofp, $sock, $options_ref, $i, $j, $max_idle, $pkt_len );
	wait_for_flow_expired( $ofp, $sock, $options_ref, $pkt_len, $pkt_total );
}

sub my_test {

	my ($sock, $options_ref) = @_;

	# send from every port to every other port
	for_all_port_pairs( $ofp, $sock, $options_ref, \&test_ip_options, 0x0);
}

run_black_box_test( \&my_test, \@ARGV );
