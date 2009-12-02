#!/usr/bin/perl -w
# test_flow_mod_check

use strict;
use OF::Includes;

sub wait_for_flow_overlap_error {
    my ($ofp, $sock, $flow_mod_pkt) = @_;
    my $rcvd_msg;

    sysread($sock, $rcvd_msg, 1512);

    my $msg_size = length($rcvd_msg);
    my $expected_size = $ofp->sizeof('ofp_error_msg') + length($flow_mod_pkt);
    compare("msg size", $msg_size, '==', $expected_size);

    my $msg = $ofp->unpack('ofp_error_msg', $rcvd_msg);
    verify_header($msg, 'OFPT_ERROR', $msg_size);

    compare("error type", $$msg{'type'}, '==', $enums{'OFPET_FLOW_MOD_FAILED'});
    compare("error code", $$msg{'code'}, '==', $enums{'OFPFMFC_OVERLAP'});
}

sub my_test {
    my ($sock, $options_ref) = @_;

    my $in_port = $$options_ref{'port_base'};
    my $out_port_1 = $in_port + 1;
    my $out_port_2 = $in_port + 2;
    my $out_port_3 = $in_port + 3;

    my $test_pkt = get_default_black_box_pkt($in_port, $out_port_1);


    my $wildcards = 0x0c0;
    my $flags = $enums{'OFPFF_CHECK_OVERLAP'};
    my $max_idle = 0x0;        # never expire
    my $flow_mod_pkt = create_flow_mod_from_udp($ofp, $test_pkt, $in_port, $out_port_1, $max_idle, $flags, $wildcards);

    # Send 'flow_mod' message
    print $sock $flow_mod_pkt;

    # Give OF switch time to process the flow mod
    usleep($$options_ref{'send_delay'});

    # change the wildcard and send again. this should fail
    $wildcards = 0x0c1;
    my $flags = $enums{'OFPFF_CHECK_OVERLAP'};
    $flow_mod_pkt = create_flow_mod_from_udp($ofp, $test_pkt, $in_port+1, $out_port_2, $max_idle, $flags, $wildcards);

    # Send 'flow_mod' message
    print $sock $flow_mod_pkt;

    wait_for_flow_overlap_error($ofp, $sock, $flow_mod_pkt);

    # Start with coarse granularity flow
    # edge-case bug reported by Justin
    # https://mailman.stanford.edu/pipermail/openflow-dev/2009-November/000529.html
    $wildcards = 0x0c1;
    $flags = 0x0;
    $flow_mod_pkt = create_flow_mod_from_udp($ofp, $test_pkt, $in_port, $out_port_1, $max_idle, $flags, $wildcards);

    # Send 'flow_mod' message
    print $sock $flow_mod_pkt;

    # Give OF switch time to process the flow mod
    usleep($$options_ref{'send_delay'});

    # change the wildcard and send again. this should fail
    $wildcards = 0x0c0;
    $flags = $enums{'OFPFF_CHECK_OVERLAP'};
    $flow_mod_pkt = create_flow_mod_from_udp($ofp, $test_pkt, $in_port+1, $out_port_2, $max_idle, $flags, $wildcards);

    # Send 'flow_mod' message
    print $sock $flow_mod_pkt;

    wait_for_flow_overlap_error($ofp, $sock, $flow_mod_pkt);



}

run_black_box_test( \&my_test, \@ARGV );
