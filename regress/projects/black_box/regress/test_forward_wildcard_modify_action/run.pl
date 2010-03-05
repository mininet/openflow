#!/usr/bin/perl -w
# test_forward_wildcard_modify_action

use strict;
use OF::Includes;

sub forward_wc_port {
	my @chg_field = ('vlan_vid', 'vlan_pcp','dl_src', 'dl_dst', 'nw_src', 'nw_dst', 'tp_src', 'tp_dst');
        foreach (@chg_field) {
                forward_simple(@_, 'port', undef, $_ );
        }
}


sub forward_wc_port_vlan {
	my @chg_field = ('strip_vlan', 'vlan_vid','vlan_pcp','dl_src', 'dl_dst', 'nw_src', 'nw_dst', 'tp_src', 'tp_dst');
	my $vlan_id = 0xa344;
		#The value was chosen at random
        foreach (@chg_field) {
                forward_simple(@_, 'port', undef, $_, $vlan_id);
        }
}

sub my_test {

	my ( $sock, $options_ref ) = @_;

	for_all_wildcards( $ofp, $sock, $options_ref, \&forward_wc_port);
	if ( not defined( $$options_ref{'no_vlan'} ) ) {
	    for_all_wildcards( $ofp, $sock, $options_ref, \&forward_wc_port_vlan);
	}
}

run_black_box_test( \&my_test, \@ARGV );

