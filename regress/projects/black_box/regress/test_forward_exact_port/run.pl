#!/usr/bin/perl -w
# test_forward_exact_port

use strict;
use OF::Includes;

sub forward_port {

	forward_simple(@_, 'port');
}

sub forward_port_vlan {
	my $vlan_id = 0xea5a;
		#[15:13] priority, [11:0] vlan id
		#The value was chosen at random
	forward_simple(@_, 'port', undef, undef, $vlan_id);
}

sub my_test {

	my ( $sock, $options_ref ) = @_;

	for_all_port_pairs( $ofp, $sock, $options_ref, \&forward_port, 0x0);
	for_all_port_pairs( $ofp, $sock, $options_ref, \&forward_port_vlan, 0x0);
}

run_black_box_test( \&my_test, \@ARGV );
