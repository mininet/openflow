#!/usr/bin/perl -w
# test_queue_forward

use strict;
use OF::Includes;

sub forward_unicast_port {
    forward_simple(@_, 'enqueue');
}

sub my_test {
    my ($sock, $options_ref) = @_;

    if ( not defined( $$options_ref{'no_slicing'} ) ) {
	for_all_port_pairs($ofp, $sock, $options_ref, \&forward_unicast_port, 0x0);
    }
}

run_black_box_test(\&my_test, \@ARGV);
