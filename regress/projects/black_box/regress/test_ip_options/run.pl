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
	my $test_pkt_args = {
		DA     => "00:00:00:00:00:0" . ( $out_port + 1 ),
		SA     => "00:00:00:00:00:0" . ( $in_port + 1 ),
		src_ip => "192.168.200." .           ( $in_port + 1 ),
		dst_ip => "192.168.201." .           ( $out_port + 1 ),
		ttl    => 64,
		len => $pkt_len - ( $#ipopt + 1 ),
		ip_options => \@ipopt,
		src_port   => 1,
		dst_port   => 0
	};
	my $test_pkt = new NF2::UDP_pkt(%$test_pkt_args);

	## ip_hdr_len is not correctly set by NF2 lib, so do it here.
	my $iphdr = $test_pkt->{'IP_hdr'};
	$$iphdr->ip_hdr_len( 5 + ( $#ipopt + 1 ) / 4 );    #set ip_hdr_len

	#print HexDump ( $test_pkt->packed );

	my $wildcards = 0x0;                               # exact match

	my $flow_mod_pkt =
	  create_flow_mod_from_udp( $ofp, $test_pkt, $in_port, $out_port, $max_idle, $wildcards );

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

sub my_test {

	my ($sock, $options_ref) = @_;

	my $max_idle =  $$options_ref{'max_idle'};
	#my $pkt_len = $$options_ref{'pkt_len'};
	my $pkt_len   = 68;
	my $pkt_total = $$options_ref{'pkt_total'};

    my $port_base = $$options_ref{'port_base'};
	my $num_ports = $$options_ref{'num_ports'};

	enable_flow_expirations( $ofp, $sock );

	# send from every port to every other port
	for ( my $i = 0 ; $i < $num_ports ; $i++ ) {
		for ( my $j = 0 ; $j < $num_ports ; $j++ ) {
			if ( $i != $j ) {
				print "sending from $i to $j\n";
				send_expect_exact( $ofp, $sock, $options_ref, $i, $j, $max_idle, $pkt_len );
				wait_for_flow_expired( $ofp, $sock, $options_ref, $pkt_len, $pkt_total );
			}
		}
	}
}

run_black_box_test( \&my_test, \@ARGV );

