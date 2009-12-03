#!/usr/bin/perl -w
# test_port_stats

use strict;
use OF::Includes;

sub forward_any {
    forward_simple(@_, 'any');
}

sub my_test {
    my ($sock, $options_ref) = @_;

    my $port_base = $$options_ref{'port_base'};
    my $num_ports = $$options_ref{'num_ports'};

    my $hdr_args = {
	version => get_of_ver(),
	type => $enums{'OFPT_STATS_REQUEST'},
	length => $ofp->sizeof('ofp_stats_request') + $ofp->sizeof('ofp_port_stats_request'), # should generate automatically!
	xid => 0x00000000
    };

    my $stats_reqhdr_args = {
	header => $hdr_args,
	type => $enums{'OFPST_PORT'},
	flags => 0
    };

    my $stats_all_ports_reqbody_args = {
	port_no => $enums{'OFPP_NONE'},
    };
    my $stats_single_port_reqbody_args = {
	port_no => 1,
    };
    my $stats_invalid_port_reqbody_args = {
	port_no => 32768,
    };

    my $stats_reqhead = $ofp->pack('ofp_stats_request', $stats_reqhdr_args);
    my $stats_all_ports_reqbody = $ofp->pack('ofp_port_stats_request', $stats_all_ports_reqbody_args);
    my $stats_single_port_reqbody = $ofp->pack('ofp_port_stats_request', $stats_single_port_reqbody_args);
    my $stats_invalid_port_reqbody = $ofp->pack('ofp_port_stats_request', $stats_invalid_port_reqbody_args);
    my $stats_all_ports_reqmsg = $stats_reqhead . $stats_all_ports_reqbody;
    my $stats_single_port_reqmsg = $stats_reqhead . $stats_single_port_reqbody;
    my $stats_invalid_port_reqmsg = $stats_reqhead . $stats_invalid_port_reqbody;

    my $stats_rephdr_args = {
	version => get_of_ver(),
	type => $enums{'OFPT_STATS_REPLY'},
	length => $ofp->sizeof('ofp_stats_reply'), # should generate automatically!
	xid => 0x00000000
    };

    my $stats_repbody_args = {
	header => $stats_rephdr_args,
	type => $enums{'OFPST_PORT'},
	flags => 0
    };

    my $stats_repbody;
    for (my $i = $port_base; $i < $port_base + $num_ports; $i++ ) {
	my $body_args = {
	    port_no => $port_base,
	    rx_count => 0,
	    tx_count => 0,
	    drop_count => 0
	};
	$stats_repbody .= $ofp->pack('ofp_port_stats', $body_args);
    }

    my $stats_repmsg = $ofp->pack('ofp_stats_reply', $stats_repbody_args) . $stats_repbody;
    my $rcvd_msg;

    # Send 'stats_request' for single port
    print $sock $stats_single_port_reqmsg;
    # Should add timeout here - will crash if no reply
    sysread($sock, $rcvd_msg, 1512) || die "Failed to receive message: $!";

    # Send 'stats_request' for invalid port
    print $sock $stats_invalid_port_reqmsg;
    # Should add timeout here - will crash if no reply
    sysread($sock, $rcvd_msg, 1512) || die "Failed to receive message: $!";

    # Send 'stats_request' for all ports
    print $sock $stats_all_ports_reqmsg;
    # Should add timeout here - will crash if no reply
    sysread($sock, $rcvd_msg, 1512) || die "Failed to receive message: $!";

    # Inspect message
    my $msg_size = length($rcvd_msg);
    my $expected_size = $ofp->sizeof('ofp_stats_reply') + 4 * $ofp->sizeof('ofp_port_stats');

    # Removed this compare because varying numbers of ports may be activated
    # compare("msg size", $msg_size, '==', $expected_size);
    my $msg = $ofp->unpack('ofp_stats_reply', $rcvd_msg);
    #print HexDump($rcvd_msg);
    #print Dumper($msg);

    # Verify fields
    verify_header($msg, 'OFPT_STATS_REPLY', $msg_size);
    compare("type", $$msg{'type'}, '==', $enums{'OFPST_PORT'});
    compare("flags", $$msg{'flags'}, '==', 0);

#   if ($rcvd_msg ne $stats_reply) {
#      die "stats reply is not what was expected"
#   }

    # TODO: Look at each received port_stats field, to ensure they equal zero...

    # Send data plane packets
    for_all_port_pairs( $ofp, $sock, $options_ref, \&forward_any, 0x1fffff);

    # TODO: Look at each received port_stats field, to ensure correct counters

    # Send 'stats_request' for all ports
    print $sock $stats_all_ports_reqmsg;
    # Should add timeout here - will crash if no reply
    sysread($sock, $rcvd_msg, 1512) || die "Failed to receive message: $!";

    # Send 'stats_request' for invalid port
    print $sock $stats_invalid_port_reqmsg;
    # Should add timeout here - will crash if no reply
    sysread($sock, $rcvd_msg, 1512) || die "Failed to receive message: $!";

    # Send 'stats_request' for single port
    print $sock $stats_single_port_reqmsg;
    # Should add timeout here - will crash if no reply
    sysread($sock, $rcvd_msg, 1512) || die "Failed to receive message: $!";
}

run_black_box_test( \&my_test, \@ARGV );
