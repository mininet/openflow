#!/usr/bin/perl -w
# test_tcp_options

use strict;
use OF::Includes;

sub create_flow_mod_from_ip {

	my ( $ofp, $udp_pkt, $in_port, $out_port, $max_idle, $flags, $wildcards, $s_port, $d_port ) = @_;

	my $hdr_args = {
		version => get_of_ver(),
		type    => $enums{'OFPT_FLOW_MOD'},
		length  => $ofp->sizeof('ofp_flow_mod') + $ofp->sizeof('ofp_action_output'),
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
	  ( ( 2**24 ) * $src_ip_subarray[0] +
		  ( 2**16 ) * $src_ip_subarray[1] +
		  ( 2**8 ) * $src_ip_subarray[2] +
		  $src_ip_subarray[3] );

	my $dst_ip =
	  ( ( 2**24 ) * $dst_ip_subarray[0] +
		  ( 2**16 ) * $dst_ip_subarray[1] +
		  ( 2**8 ) * $dst_ip_subarray[2] +
		  $dst_ip_subarray[3] );

	# read IP_header protocol field
	my $iph   = $udp_pkt->{'IP_hdr'};
	my $proto = $$iph->proto();

	my $match_args = {
		wildcards => $wildcards,
		in_port   => $in_port,
		dl_src    => \@src_mac_subarray,
		dl_dst    => \@dst_mac_subarray,
		dl_vlan   => 0xffff,
		dl_vlan_pcp => 0x00,
		dl_type   => 0x0800,
		nw_src    => $src_ip,
		nw_dst    => $dst_ip,
		nw_proto  => $proto,               #any protocol
		tp_src    => $s_port,
		tp_dst    => $d_port
	};

	print "My Out Port: ${out_port}\n";
	my $action_output_args = {
		type => $enums{'OFPAT_OUTPUT'},
		len => $ofp->sizeof('ofp_action_output'),
		port    => $out_port,
		max_len => 0                      # send entire packet
	};
	my $action_output = $ofp->pack('ofp_action_output', $action_output_args);

	my $flow_mod_args = {
		header => $hdr_args,
		match  => $match_args,
		command   => $enums{'OFPFC_ADD'},
		idle_timeout  => $max_idle,
		hard_timeout  => $max_idle,
		flags => $flags,
		priority => 0,
		buffer_id => -1
	};
	my $flow_mod = $ofp->pack( 'ofp_flow_mod', $flow_mod_args );

	my $flow_mod_pkt = $flow_mod . $action_output;

	return $flow_mod_pkt;
}

sub send_tcp_op_expect_exact {

	my ( $ofp, $sock, $options_ref, $in_port_offset, $out_port_offset, $max_idle, $pkt_len ) = @_;

	my $in_port = $in_port_offset + $$options_ref{'port_base'};
	my $out_port = $out_port_offset + $$options_ref{'port_base'};		

	my $src_tcp_port = 70;
	my $dst_tcp_port = 80;

	# in_port refers to the flow mod entry's input
	my @tcp_payload = (    # 30 bytes
		0x00, 0x46, 0x00, 0x50,    # $src_tcp_port, $dst_tcp_port (should set automatically)
		0x01, 0x23, 0x45, 0x67,    #Seq
		0x01, 0x23, 0x45, 0x00,    #Ack
		0x58, 0x23, 0x00, 0x11,    #Offset, Flag, Win
		0xaa, 0xbb, 0x00, 0x00,    #Chksum, Urgent
		0x03, 0x03, 0x02, 0x00,    #TCP Option
		0xaa, 0xbb, 0xcc, 0xdd,    #TCP Content
		0xee, 0xff                 #TCP Content
	);
	my $test_pkt_args = {
		DA     => "00:00:00:00:00:" . sprintf( "%02d", $out_port ),
		SA     => "00:00:00:00:00:" . sprintf( "%02d", $in_port ),
		src_ip => "192.168.200." .     ( $in_port ),
		dst_ip => "192.168.201." .     ( $out_port ),
		ttl    => 64,
		len    => $pkt_len,
		proto => 6,                # TCP protocol id
	};

	my $test_pkt = new NF2::IP_pkt(%$test_pkt_args);
	my $payload  = $test_pkt->{'payload'};
	$$payload->set_bytes(@tcp_payload);

	#print HexDump ( $test_pkt->packed );

	#my $wildcards = 0;           # exact match
	my $wildcards =  $enums{'OFPFW_TP_SRC'} | 
		$enums{'OFPFW_TP_DST'};# | 
	#	$enums{'OFPFW_NW_PROTO'};     # wildcard match (don't care udp src/dst ports)

	my $flags = $enums{'OFPFF_SEND_FLOW_REM'};
	my $flow_mod_pkt =
	  create_flow_mod_from_ip( $ofp, $test_pkt, $in_port, $out_port, $max_idle, $flags, $wildcards,
		$src_tcp_port, $dst_tcp_port );

	#print HexDump($flow_mod_pkt);

	# Send 'flow_mod' message
	print $sock $flow_mod_pkt;
	print "sent flow_mod message\n";
	usleep($$options_ref{'send_delay'});

	# Send a packet - ensure packet comes out desired port
	nftest_send( "eth" . ( $in_port_offset + 1), $test_pkt->packed );
	nftest_expect( "eth" . ( $out_port_offset + 1 ), $test_pkt->packed );
}

sub test_tcp_options {
	my ( $ofp, $sock, $options_ref, $i, $j, $wildcards ) = @_;

	my $max_idle = $$options_ref{'max_idle'};
	#my $pkt_len = $$options_ref{'pkt_len'};
	my $pkt_len = 64;    # len = 14(Ethr_hdr)+ 20(IP_header)+ 30(TCP_header+Option)
	                     # = 64 (IPlen = 50)
	my $pkt_total = $$options_ref{'pkt_total'};

	send_tcp_op_expect_exact( $ofp, $sock, $options_ref, $i, $j, $max_idle, $pkt_len );
	#sleep(5);
	wait_for_flow_expired( $ofp, $sock, $options_ref, $pkt_len, $pkt_total );
}

sub my_test {
	my ( $sock, $options_ref ) = @_;

	# send from every port to every other port
	for_all_port_pairs( $ofp, $sock, $options_ref, \&test_tcp_options, 0x0);
}

run_black_box_test( \&my_test, \@ARGV );
