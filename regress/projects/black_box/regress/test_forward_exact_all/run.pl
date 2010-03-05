#!/usr/bin/perl -w
# test_forward_exact_all

use strict;
use OF::Includes;

sub forward_all {

	forward_simple(@_, 'all');
}

sub forward_all_vlan {
        my $vlan_id = 0xa5f3;
                #[15:13] priority, [11:0] vlan id
		#The value was chosen at random
        forward_simple(@_, 'all', undef, undef, $vlan_id);
}


sub my_test {

	my ( $sock, $options_ref ) = @_;

	for_all_ports( $ofp, $sock, $options_ref, \&forward_all, 0x0);
	if ( not defined( $$options_ref{'no_vlan'} ) ) {
	    for_all_ports( $ofp, $sock, $options_ref, \&forward_all_vlan, 0x0);
	}
}

run_black_box_test( \&my_test, \@ARGV );
