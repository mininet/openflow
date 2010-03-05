#!/usr/bin/perl -w
# test_ip_protocol (case e, not TCP nor UDP, but specify src port!=0, dst port!=0);

use strict;
use OF::Includes;

sub send_expect_exact {

	my ( $ofp, $sock, $in_port, $out_port, $max_idle, $pkt_len ) = @_;

	# in_port refers to the flow mod entry's input

	my $test_pkt_args = {
		DA     => "00:00:00:00:00:" . sprintf( "%02d", $out_port ),
		SA     => "00:00:00:00:00:" . sprintf( "%02d", $in_port ),
		src_ip => "192.168.200." .           ( $in_port ),
		dst_ip => "192.168.201." .           ( $out_port ),
		ttl    => 64,
		len    => $pkt_len,
		src_port => 70,
		dst_port => 80
	};
	my $test_pkt = new NF2::UDP_pkt(%$test_pkt_args);

	## Change protoco field
	my $iphdr=$test_pkt->{'IP_hdr'};
	$$iphdr->proto(0x13); # overwrite protocol filed in IP header

	#print HexDump ( $test_pkt->packed );

	my $wildcards = 0x0; # exact match

	my $flow_mod_pkt =
	  create_flow_mod_from_ip( $ofp, $test_pkt, $in_port, $out_port,
		$max_idle, $wildcards, 3, 4);

	#print HexDump($flow_mod_pkt);

	# Send 'flow_mod' message
	print $sock $flow_mod_pkt;
	print "sent flow_mod message\n";
	usleep(100000);
	

	# Send a packet - ensure packet comes out desired port
	nftest_send( "eth" . ( $in_port + 1 ),
		$test_pkt->packed );
	nftest_expect( "eth" . ( $out_port + 1 ),
		$test_pkt->packed );
}


sub my_test {
	
	my ($sock, $options_ref) = @_;

	my $max_idle = $$options_ref{'max_idle'};
	my $pkt_len = $$options_ref{'pkt_len'};
	my $pkt_total = $$options_ref{'pkt_total'};

	# send from every port to every other port
	for ( my $i = 0 ; $i < 4 ; $i++ ) {
		for ( my $j = 0 ; $j < 4 ; $j++ ) {
			if ( $i != $j ) {
				print "sending from $i to $j\n";
				send_expect_exact( $ofp, $sock, $i, $j, $max_idle, $pkt_len );
				wait_for_flow_expired_all( $ofp, $sock, $options_ref );
			}
		}
	}
}

sub create_flow_mod_from_ip {

	my ( $ofp, $udp_pkt, $in_port, $out_port, $max_idle, $wildcards, $s_port, $d_port ) = @_;

	my $hdr_args = {
		version => get_of_ver(),
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
	my $eth_hdr_bytes = $$ref_to_eth_hdr->{'bytes'};
	my $ip_hdr_bytes  = $$ref_to_ip_hdr->{'bytes'};
	my @dst_mac_subarray = @{$eth_hdr_bytes}[ 0 .. 5 ];
	my @src_mac_subarray = @{$eth_hdr_bytes}[ 6 .. 11 ];

	my @src_ip_subarray = @{$ip_hdr_bytes}[ 12 .. 15 ];
	my @dst_ip_subarray = @{$ip_hdr_bytes}[ 16 .. 19 ];

	my $src_ip =
	  ( ( 2**24 ) * $src_ip_subarray[0] + ( 2**16 ) * $src_ip_subarray[1] +
		  ( 2**8 ) * $src_ip_subarray[2] + $src_ip_subarray[3] );

	my $dst_ip =
	  ( ( 2**24 ) * $dst_ip_subarray[0] + ( 2**16 ) * $dst_ip_subarray[1] +
		  ( 2**8 ) * $dst_ip_subarray[2] + $dst_ip_subarray[3] );

	# read IP_header protocol field
	my $iph = $udp_pkt->{'IP_hdr'};
	my $proto = $$iph->proto();

	my $match_args = {
		wildcards => $wildcards,
		in_port   => $in_port,
		dl_src    => \@src_mac_subarray,
		dl_dst    => \@dst_mac_subarray,
		dl_vlan   => 0xffff,
		dl_type   => 0x0800,
		nw_src    => $src_ip,
		nw_dst    => $dst_ip,
		nw_proto  => $proto, #any protocol 
		tp_src    => $s_port,
		tp_dst    => $d_port
	};

	my $action_output_args = {
		max_len => 0,                                     # send entire packet
		port    => $out_port
	};
	print "My Out Port: ${out_port}\n";

	my $action_args = {
		type => $enums{'OFPAT_OUTPUT'},
		arg  => { output => $action_output_args }
	};
	my $action = $ofp->pack( 'ofp_action', $action_args );

	my $flow_mod_args = {
		header    => $hdr_args,
		match     => $match_args,
		command   => $enums{'OFPFC_ADD'},
		max_idle  => $max_idle,
		buffer_id => 0x0000,
		group_id  => 0
	};
	my $flow_mod = $ofp->pack( 'ofp_flow_mod', $flow_mod_args );

	my $flow_mod_pkt = $flow_mod . $action;

	return $flow_mod_pkt;
}

run_black_box_test(\&my_test);
