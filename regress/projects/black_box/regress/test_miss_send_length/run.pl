#!/usr/bin/perl -w
# test_packet_in
# Send a packet of size 256B, and ensure that it gets reduced to 128B

use strict;
use OF::Includes;

sub verify_packet_in {
    my ($sock, $options_ref, $miss_send_len, $pktsiz, $expected_pktsiz) = @_;

    my $in_port = $$options_ref{'port_base'};
    my $out_port = $in_port + 1;

    # Give OF switch time to process the set_config
    usleep($$options_ref{'send_delay'});

    my $pkt = get_default_black_box_pkt_len($in_port, $out_port, $pktsiz);
    nftest_send('eth1', $pkt->packed);
    print "Sent test packet for len ".$miss_send_len."...\n";

    my $rcvd_msg;
    sysread($sock, $rcvd_msg, 1512) || die "Failed to receive message: $!";

    # Inspect  message
    my $msg_size = length($rcvd_msg);
    compare("msg size", $msg_size, '==', $expected_pktsiz);

    my $msg = $ofp->unpack('ofp_packet_in', $rcvd_msg);
    #print HexDump ($rcvd_msg);
    #print Dumper($msg);

    # Verify fields
    verify_header($msg, 'OFPT_PACKET_IN', $msg_size);

    # total len should be full length of original sent frame
    compare("total len", $$msg{'total_len'}, '==', length($pkt->packed));
    compare("in_port", $$msg{'in_port'}, '==', $in_port);
    compare("reason", $$msg{'reason'}, '==', $enums{'OFPR_NO_MATCH'});

    # verify packet was unchanged!
    my $rcvd_pkt_data = substr($rcvd_msg, $ofp->offsetof('ofp_packet_in', 'data'));

    # trim to MISS_SEND_LEN
    my $pkt_trimmed = substr($pkt->packed, 0, $miss_send_len);
    if ($rcvd_pkt_data ne $pkt_trimmed) {
	die "ERROR: received packet data didn't match packet sent\n";
    }
}

sub my_test {
    my ($sock, $options_ref) = @_;

    my $miss_send_len = get_of_miss_send_len_default();
    my $pktsiz = 63;
    my $expected_pktsiz = 8 + 10 + $pktsiz;
    verify_packet_in($sock, $options_ref, $miss_send_len, $pktsiz, $expected_pktsiz);

    $miss_send_len = 0;
    $pktsiz = 67;
    $expected_pktsiz = 8 + 10;
    set_config($ofp, $sock, $options_ref, 1, $miss_send_len);
    verify_packet_in($sock, $options_ref, $miss_send_len, $pktsiz, $expected_pktsiz);

    $miss_send_len = 127;
    $pktsiz = 259;
    $expected_pktsiz = 8 + 10 + $miss_send_len;
    set_config($ofp, $sock, $options_ref, 1, $miss_send_len);
    verify_packet_in($sock, $options_ref, $miss_send_len, $pktsiz, $expected_pktsiz);

    $miss_send_len = 65535;
    $pktsiz = 1500 - 8 - 10;
    $expected_pktsiz = 1500;
    set_config($ofp, $sock, $options_ref, 1, $miss_send_len);
    verify_packet_in($sock, $options_ref, $miss_send_len, $pktsiz, $expected_pktsiz);

    set_config($ofp, $sock, $options_ref, 1, get_of_miss_send_len_default());
}

run_black_box_test(\&my_test, \@ARGV);
