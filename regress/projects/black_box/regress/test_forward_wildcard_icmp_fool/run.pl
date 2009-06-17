#!/usr/bin/perl -w
# test_forward_wildcard_icmp_port

use strict;
use OF::Includes;

sub forward_wc_port {
	forward_simple_icmp(@_, 'port', 1);  # 1: fool_flg = on
}

sub my_test {

	my ( $sock, $options_ref ) = @_;

	for_all_wildcards( $ofp, $sock, $options_ref, \&forward_wc_port);
}

run_black_box_test( \&my_test, \@ARGV );


