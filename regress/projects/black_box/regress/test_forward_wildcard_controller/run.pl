#!/usr/bin/perl -w
# test_forward_wildcard_controller

use strict;
use OF::Includes;

sub forward_wc_controller {

	forward_simple(@_, 'controller');
}

sub forward_wc_controller_vlan {
        my $vlan_id = 0x4abc;
                #[15:13] priority, [11:0] vlan id
		#The value was chosen at random
        forward_simple(@_, 'controller', undef, undef, $vlan_id);
}

sub my_test {

	my ( $sock, $options_ref ) = @_;

	for_all_wildcards( $ofp, $sock, $options_ref, \&forward_wc_controller);
	if ( not defined( $$options_ref{'no_vlan'} ) ) {
	    for_all_wildcards( $ofp, $sock, $options_ref, \&forward_wc_controller_vlan);
	}
}

run_black_box_test( \&my_test, \@ARGV );

