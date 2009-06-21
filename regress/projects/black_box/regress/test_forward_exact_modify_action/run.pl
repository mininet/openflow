#!/usr/bin/perl -w
# test_forward_exact_modify_action

use strict;
use OF::Includes;

sub forward_port {

	my @chg_field = ('vlan_vid', 'vlan_pcp', 'dl_src', 'dl_dst', 'nw_src', 'nw_dst', 'tp_src', 'tp_dst');
	foreach (@chg_field) {
		forward_simple(@_, 'port', undef, $_ );
	}
}

sub forward_port_vlan {
	my @chg_field = ('strip_vlan', 'vlan_vid', 'vlan_pcp', 'dl_src', 'dl_dst', 'nw_src', 'nw_dst', 'tp_src', 'tp_dst');
	my $vlan = 0x65a1;
		#[15:13]:vlan_pcp, [11:0]:vlan_vid
		#The value was chosen at random
	foreach (@chg_field) {
		forward_simple(@_, 'port', undef, $_, $vlan );
	}
}
sub my_test {

	my ( $sock, $options_ref ) = @_;

	for_all_port_pairs( $ofp, $sock, $options_ref, \&forward_port, 0x0);
	for_all_port_pairs( $ofp, $sock, $options_ref, \&forward_port_vlan, 0x0);
}

run_black_box_test( \&my_test, \@ARGV );
