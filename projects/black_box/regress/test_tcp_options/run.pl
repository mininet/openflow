#!/usr/bin/perl -w
# test_tcp_options

use strict;
use OF::Includes;

my $pkt_len   = 64; # len = 14(Ethr_hdr)+ 20(IP_header)+ 30(TCP_header+Option)
                    # = 64 (IPlen = 50)
my $pkt_total = 1;
my $max_idle  = 1;

sub send_tcp_op_expect_exact {

	my ( $ofp, $sock, $in_port, $out_port, $max_idle, $pkt_len ) = @_;

	my $src_tcp_port = 70;
	my $dst_tcp_port = 80;

	# in_port refers to the flow mod entry's input
	my @tcp_payload = (      # 30 bytes
		 0x00,0x46,0x00,0x50, # $src_tcp_port, $dst_tcp_port (should set automatically)
		 0x01,0x23,0x45,0x67, #Seq
		 0x01,0x23,0x45,0x00, #Ack
		 0x18,0x23,0x00,0x11, #Offset, Flag, Win
		 0xaa,0xbb,0x00,0x00, #Chksum, Urgent
		 0x03,0x03,0x02,0x00,  #TCP Option
		 0xaa,0xbb,0xcc,0xdd,  #TCP Content
		 0xee,0xff  #TCP Content
	 );
	my $test_pkt_args = {
		DA     => "00:00:00:00:00:0" . ( $out_port + 1 ),
		SA     => "00:00:00:00:00:0" . ( $in_port + 1 ),
		src_ip => "0.0.0." .           ( $in_port + 1 ),
		dst_ip => "0.0.0." .           ( $out_port + 1 ),
		ttl => 64,
		len => $pkt_len,
		proto => 6,           # TCP protocol id
		ttl    => 64,
		len    => $pkt_len
        };

	my $test_pkt = new NF2::IP_pkt(%$test_pkt_args);
	my $payload=$test_pkt->{'payload'};
	$$payload->set_bytes(@tcp_payload);

	#print HexDump ( $test_pkt->packed );

	my $wildcards = 0x0; # exact match

	my $flow_mod_pkt =
	  create_flow_mod_from_ip( $ofp, $test_pkt, $in_port, $out_port,
				   $max_idle, $wildcards, $src_tcp_port, $dst_tcp_port);

	#print HexDump($flow_mod_pkt);

	# Send 'flow_mod' message
	print $sock $flow_mod_pkt;
	print "sent flow_mod message\n";
	usleep(100000);
	

	# Send a packet - ensure packet comes out desired port
	nftest_send( nftest_get_iface( "eth" . ( $in_port + 1 ) ),
		$test_pkt->packed );
	nftest_expect( nftest_get_iface( "eth" . ( $out_port + 1 ) ),
		$test_pkt->packed );
}


sub my_test {
	
	my ($sock) = @_;

	# send from every port to every other port
	for ( my $i = 0 ; $i < 4 ; $i++ ) {
		for ( my $j = 0 ; $j < 4 ; $j++ ) {
			if ( $i != $j ) {
				print "sending from $i to $j\n";
				send_tcp_op_expect_exact( $ofp, $sock, $i, $j, $max_idle, $pkt_len );
				wait_for_flow_expired( $ofp, $sock, $pkt_len, $pkt_total );
			}
		}
	}
}


sub create_flow_mod_from_ip {

	my ( $ofp, $udp_pkt, $in_port, $out_port, $max_idle, $wildcards, $s_port, $d_port ) = @_;

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


