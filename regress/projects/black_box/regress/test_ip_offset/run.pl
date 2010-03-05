#!/usr/bin/perl -w
# test_ip_offset

use strict;
use OF::Includes;

sub send_expect_exact {

	my ( $ofp, $sock, $options_ref, $in_port_offset, $out_port_offset, $max_idle, $pkt_len ) = @_;

	my $in_port = $in_port_offset + $$options_ref{'port_base'};
	my $out_port = $out_port_offset + $$options_ref{'port_base'};		
	
	# in_port refers to the flow mod entry's input

	my $test_pkt_frag_args = {
		DA     => "00:00:00:00:00:" . sprintf( "%02d", $out_port ),
		SA     => "00:00:00:00:00:" . sprintf( "%02d", $in_port ),
		src_ip => "192.168.200." .     ( $in_port ),
		dst_ip => "192.168.201." .     ( $out_port ),
		ttl    => 64,
		len    => $pkt_len,
		frag     => 0x2fff,    # IP_frag > IP_len
		src_port => 1,
		dst_port => 0
	};
	my $test_pkt_frag = new NF2::UDP_pkt(%$test_pkt_frag_args);

	my $test_pkt_args = {
		DA     => "00:00:00:00:00:" . sprintf( "%02d", $out_port ),
		SA     => "00:00:00:00:00:" . sprintf( "%02d", $in_port ),
		src_ip => "192.168.200." .     ( $in_port ),
		dst_ip => "192.168.201." .     ( $out_port ),
		ttl    => 64,
		len    => $pkt_len,
		frag     => 0, 
		src_port => 0,
		dst_port => 0
	};
	my $test_pkt = new NF2::UDP_pkt(%$test_pkt_args);

	#print HexDump ( $test_pkt->packed );

	my $wildcards = 0x0;       # exact match
	my $flags = $enums{'OFPFF_SEND_FLOW_REM'};

	my $flow_mod_pkt =
	  create_flow_mod_from_udp( $ofp, $test_pkt, $in_port, $out_port, $max_idle, $flags, $wildcards );

	#print HexDump($flow_mod_pkt);

	# Send 'flow_mod' message
	print $sock $flow_mod_pkt;
	print "sent flow_mod message\n";
	usleep($$options_ref{'send_delay'});

	# Send a packet - ensure packet comes out desired port
	nftest_send( "eth" . ( $in_port_offset + 1 ), $test_pkt_frag->packed );
	nftest_expect( "eth" . ( $out_port_offset + 1 ), $test_pkt_frag->packed );
}

sub test_ip_offset {

	my ( $ofp, $sock, $options_ref, $i, $j, $wildcards ) = @_;

	my $max_idle  = $$options_ref{'max_idle'};
	my $pkt_len   = $$options_ref{'pkt_len'};
	my $pkt_total = $$options_ref{'pkt_total'};

	my $port_base = $$options_ref{'port_base'};
	my $num_ports = $$options_ref{'num_ports'};
	
	send_expect_exact( $ofp, $sock, $options_ref, $i, $j, $max_idle, $pkt_len );
	wait_for_flow_expired_all( $ofp, $sock, $options_ref );
}

sub my_test {

	my ( $sock, $options_ref ) = @_;

	# send from every port to every other port
	for_all_port_pairs( $ofp, $sock, $options_ref, \&test_ip_offset, 0x0);
}

run_black_box_test( \&my_test, \@ARGV );
