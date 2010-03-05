#!/usr/bin/perl -w
# test_forward_exact_controller

use strict;
use OF::Includes;

use strict;
use OF::Includes;

sub forward_controller {

	forward_simple(@_, 'controller');
}

sub forward_controller_vlan {
        my $vlan_id = 0xc123;
                #[15:13] priority, [11:0] vlan id
		#The value was chosen at random
        forward_simple(@_, 'controller', undef, undef, $vlan_id);
}

sub my_test {

	my ( $sock, $options_ref ) = @_;

	for_all_ports( $ofp, $sock, $options_ref, \&forward_controller, 0x0);
	if ( not defined( $$options_ref{'no_vlan'} ) ) {
	    for_all_ports( $ofp, $sock, $options_ref, \&forward_controller_vlan, 0x0);
	}
}

run_black_box_test( \&my_test, \@ARGV );
