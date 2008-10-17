#!/usr/bin/perl -w
# test_forward_wildcard_controller

use strict;
use OF::Includes;

sub forward_wc_controller {

	forward_simple(@_, 'controller');
}

sub my_test {

	my ( $sock, $options_ref ) = @_;

	enable_flow_expirations( $ofp, $sock );

	for_all_wildcards( $ofp, $sock, $options_ref, \&forward_wc_controller);
}

run_black_box_test( \&my_test, \@ARGV );

