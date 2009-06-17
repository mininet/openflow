#!/usr/bin/perl -w
# test_drop_exact

use strict;
use OF::Includes;

#sub drop_simple {
#
#	my ( $ofp, $sock, $options_ref, $in_port_offset, $out_port_offset, $wildcards, $nowait ) = @_;
#
#	my $in_port = $in_port_offset + $$options_ref{'port_base'};
#	my $out_port = $out_port_offset + $$options_ref{'port_base'};		
#	# print "drop_simple : ports = ".($in_port).",".($out_port);
#
#	my $test_pkt = get_default_black_box_pkt_len( $in_port, $out_port, $$options_ref{'pkt_len'} );
#
#	#print HexDump ( $test_pkt->packed );
#
#	my $flow_mod_pkt =
#	  create_flow_drop_from_udp_action( $ofp, $test_pkt, $in_port, $out_port, $$options_ref{'max_idle'}, $wildcards, 'drop' );
#
#	#print HexDump($flow_mod_pkt);
#	#print Dumper($flow_mod_pkt);
#
#	# Send 'flow_mod' message
#	syswrite( $sock, $flow_mod_pkt );
#	print "sent flow_mod message\n";
#	
#	# Give OF switch time to process the flow mod
#	usleep($$options_ref{'send_delay'});
#
#	nftest_send( "eth" . ($in_port_offset + 1), $test_pkt->packed);
#	
#	# We should expect no message at all on any port ! - Jean II
#
#	if (not defined($nowait)) {
#		print "wait \n";
#		wait_for_flow_expired_all( $ofp, $sock, $options_ref );	
#	}
#}

sub drop_port {

	forward_simple(@_, 'drop');
}

sub my_test {

	my ( $sock, $options_ref ) = @_;

	for_all_port_pairs( $ofp, $sock, $options_ref, \&drop_port, 0x0);
}

run_black_box_test( \&my_test, \@ARGV );
