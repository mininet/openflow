#!/usr/bin/perl -w
# test_forward_exact_modify_action

use strict;
use OF::Includes;

sub forward_port {

	my @chg_field = ('dl_src', 'dl_dst', 'nw_src', 'nw_dst', 
'tp_src', 'tp_dst');
	foreach (@chg_field) {
		forward_simple(@_, 'port', undef, $_ );
	}

}

sub my_test {

	my ( $sock, $options_ref ) = @_;

	enable_flow_expirations( $ofp, $sock );

	for_all_port_pairs( $ofp, $sock, $options_ref, \&forward_port, 0x0);
}

run_black_box_test( \&my_test, \@ARGV );
