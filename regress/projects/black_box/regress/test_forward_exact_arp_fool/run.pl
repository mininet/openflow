#!/usr/bin/perl -w
# test_forward_exact_arp_fool

use strict;
use OF::Includes;

sub forward_port {

	forward_simple_arp(@_, 'port', 1);  # 1: fool_flg=on
}

sub my_test {

	my ( $sock, $options_ref ) = @_;

	for_all_port_pairs( $ofp, $sock, $options_ref, \&forward_port, 0x0);
}

run_black_box_test( \&my_test, \@ARGV );
