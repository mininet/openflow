#!/usr/bin/perl -w
# test_delete

use strict;
use OF::Includes;

sub send_expect_exact_with_wildcard {

	my ( $ofp, $sock, $options_ref, $in_port_offset, $out_port_offset, $out_port2_offset, $max_idle, $pkt_len ) = @_;

	my $in_port = $in_port_offset + $$options_ref{'port_base'};
	my $out_port = $out_port_offset + $$options_ref{'port_base'};
	my $out_port2 = $out_port2_offset + $$options_ref{'port_base'};

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

	my $test_pkt_args2 = {
		DA     => "00:00:00:00:00:" . sprintf( "%02d", $out_port ),
		SA     => "00:00:00:00:00:" . sprintf( "%02d", $in_port ),
		src_ip => "192.168.200." .           ( $in_port ),
		dst_ip => "192.168.201." .           ( $out_port ),
		ttl    => 64,
		len    => $pkt_len,
		src_port => 170,
		dst_port => 180
	};
	my $test_pkt2 = new NF2::UDP_pkt(%$test_pkt_args2);

	# Flow entry -- exact match, $out_port
	my $wildcards = 0x0;    # exact match
	my $flags = 0x0;        # don't send flow expiry
	my $flow_mod_exact_pkt =
	  create_flow_mod_from_udp( $ofp, $test_pkt, $in_port, $out_port, $max_idle, $flags, $wildcards );

	# 2nd flow entry -- wildcard match, $out_port2
	$wildcards =  $enums{'OFPFW_TP_SRC'} | $enums{'OFPFW_TP_DST'};     # wildcard match (don't care udp src/dst ports)
	print "wildcards = $wildcards\n";
	my $flow_mod_wildcard_pkt =
	  create_flow_mod_from_udp( $ofp, $test_pkt, $in_port, $out_port2, $max_idle, $flags, $wildcards );

	#print HexDump($flow_mod_exact_pkt);
	#print HexDump($flow_mod_wildcard_pkt);

	# Send 'flow_mod' message
	print $sock $flow_mod_exact_pkt;
	print "sent flow_mod message (create exact match entry)\n";

	# Give OF switch time to process the flow mod
	usleep($$options_ref{'send_delay'});

	print $sock $flow_mod_wildcard_pkt;
	print "sent flow_mod message (create wildcard entry)\n";
	
	# Give OF switch time to process the flow mod
	usleep($$options_ref{'send_delay'});

	# Check what's on the switch
	#dpctl_show_flows($options_ref);

	# Send a packet - ensure packet comes out desired port
	print "Verify packets are forwarded correctly\n";
	nftest_send( "eth" . ( $in_port_offset + 1 ), $test_pkt->packed );
	nftest_expect( "eth" . ( $out_port_offset + 1 ), $test_pkt->packed );

	nftest_send( "eth" . ( $in_port_offset + 1 ), $test_pkt2->packed );
	nftest_expect( "eth" . ( $out_port2_offset + 1 ), $test_pkt2->packed );
	
	print "sent two packets\n";
}

sub delete_send_expect {

	my ( $ofp, $sock, $options_ref, $in_port_offset, $out_port_offset, $out_port2_offset, $max_idle, $pkt_len ) = @_;

	my $in_port = $in_port_offset + $$options_ref{'port_base'};
	my $out_port = $out_port_offset + $$options_ref{'port_base'};
	my $out_port2 = $out_port2_offset + $$options_ref{'port_base'};

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

	my $test_pkt_args2 = {
		DA     => "00:00:00:00:00:" . sprintf( "%02d", $out_port ),
		SA     => "00:00:00:00:00:" . sprintf( "%02d", $in_port ),
		src_ip => "192.168.200." .           ( $in_port ),
		dst_ip => "192.168.201." .           ( $out_port ),
		ttl    => 64,
		len    => $pkt_len,
		src_port => 170,
		dst_port => 180
	};
	my $test_pkt2 = new NF2::UDP_pkt(%$test_pkt_args2);

	my $wildcards =  $enums{'OFPFW_TP_SRC'} | $enums{'OFPFW_TP_DST'};     # wildcard match (don't care udp src/dst ports)
	my $flags = 0x0;        # don't send flow expiry
	my $flow_mod_wildcard_pkt =
	  create_flow_mod_from_udp_action( $ofp, $test_pkt2, $in_port, $out_port2, $max_idle,
		$flags, $wildcards, "OFPFC_DELETE" );

	#print HexDump($flow_mod_exact_pkt);
	#print HexDump($flow_mod_wildcard_pkt);
 
	# Send 'flow_mod' message (delete wildcard entry without STRICT)
	print $sock $flow_mod_wildcard_pkt;
	print "sent flow_mod message (delete wildcard entry)\n";

	# Give OF switch time to process the flow mod
	usleep($$options_ref{'send_delay'});
 	# Give extra time, wildcard delete takes more time - Jean II
 	usleep($$options_ref{'send_delay'});

	# Check what's on the switch
	#dpctl_show_flows($options_ref);

	# Send a packet
	print "Verify packets are forwarded correctly i.e., fwded to contoller\n";
	nftest_send( "eth" . ( $in_port_offset + 1 ), $test_pkt->packed );
	nftest_send( "eth" . ( $in_port_offset + 1 ), $test_pkt2->packed );

	# both pkts should go to the controller
	wait_for_one_packet_in( $ofp, $sock, $pkt_len, $test_pkt->packed );
	wait_for_one_packet_in( $ofp, $sock, $pkt_len, $test_pkt2->packed );

}

sub test_delete {

	my ( $ofp, $sock, $options_ref, $i, $j, $o_port2, $wildcards ) = @_;

	my $max_idle =  $$options_ref{'max_idle'};
	my $pkt_len = $$options_ref{'pkt_len'};
	my $pkt_total = $$options_ref{'pkt_total'};

	print "sending from $i to $j & $i to $o_port2 -- both should match\n";
	send_expect_exact_with_wildcard( $ofp, $sock, $options_ref, $i, $j, $o_port2, $max_idle, $pkt_len );

	# wait for switch to process last packets
	usleep($$options_ref{'send_delay'});

	print "delete wildcard entry (without STRICT) and send packets again\n";
	delete_send_expect( $ofp, $sock, $options_ref, $i, $j, $o_port2, $max_idle, $pkt_len );
}

sub my_test {

	my ($sock, $options_ref) = @_;

	# send from every port to every other port
	for_all_port_triplets( $ofp, $sock, $options_ref, \&test_delete, 0x0);
}

run_black_box_test( \&my_test, \@ARGV );
