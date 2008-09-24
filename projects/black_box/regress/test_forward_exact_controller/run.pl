#!/usr/bin/perl -w
# test_forward_exact_controller

use strict;
use OF::Includes;

use strict;
use OF::Includes;

sub forward_controller {

	forward_simple(@_, 'controller');
}

sub my_test {

	my ( $sock, $options_ref ) = @_;

	enable_flow_expirations( $ofp, $sock );

	for_all_ports( $ofp, $sock, $options_ref, \&forward_controller, 0x0);
}

run_black_box_test( \&my_test, \@ARGV );
