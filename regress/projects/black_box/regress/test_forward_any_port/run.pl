#!/usr/bin/perl -w
# test_forward_any_port

use strict;
use OF::Includes;

sub forward_any {

	forward_simple(@_, 'any');
}

sub my_test {

	my ( $sock, $options_ref ) = @_;

	for_all_port_pairs( $ofp, $sock, $options_ref, \&forward_any, 0xfffff);
}

run_black_box_test( \&my_test, \@ARGV );

