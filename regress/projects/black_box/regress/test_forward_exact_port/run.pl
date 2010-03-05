#!/usr/bin/perl -w
# test_forward_exact_port

use strict;
use OF::Includes;

sub forward_unicast_port {
    forward_simple(@_, 'port');
}

sub forward_unicast_vlan_port {
    my $vlan_id = 0xea5a;
    #[15:13] priority, [11:0] vlan id
    #The value was chosen at random
    forward_simple(@_, 'port', undef, undef, $vlan_id);
}

sub my_test {
    my ($sock, $options_ref) = @_;

    for_all_port_pairs($ofp, $sock, $options_ref, \&forward_unicast_port, 0x0);
    if ( not defined( $$options_ref{'no_vlan'} ) ) {
	for_all_port_pairs($ofp, $sock, $options_ref, \&forward_unicast_vlan_port, 0x0);
    }
}

run_black_box_test(\&my_test, \@ARGV);
