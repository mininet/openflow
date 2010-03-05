#!/usr/bin/perl -w
# test_queue_stats

use strict;
use OF::Includes;

sub my_test {

    my ( $sock, $options_ref ) = @_;

    if ( not defined( $$options_ref{'no_slicing'} ) ) {

	my $port_base = $$options_ref{'port_base'};
	my $num_ports = $$options_ref{'num_ports'};
        
	# Prepare stats request
	my $hdr_args = {
	    version => get_of_ver(),
	    type    => $enums{'OFPT_STATS_REQUEST'},
	    length  => $ofp->sizeof('ofp_stats_request') + $ofp->sizeof('ofp_queue_stats_request'),        # should generate automatically!
	    xid     => 0x00000000
	};

	my @pad_2 = (0,0);
	my $body_args = {
	    port_no      => $port_base,
	    pad          => \@pad_2,
	    queue_id     => 0xffffffff          # TODO : export get_define to get OFPQ_ALL
	};


	my $stats_request_args = {
	    header        => $hdr_args,
	    type          => $enums{'OFPST_QUEUE'},
	    flags          => 0
	};

	my $request_body = $ofp->pack( 'ofp_queue_stats_request', $body_args );
	my $stats_request = $ofp->pack( 'ofp_stats_request', $stats_request_args ) . $request_body;
    

	# Prepare expected stats reply
	my $reply_hdr_args = {
	    version => get_of_ver(),
	    type    => $enums{'OFPT_STATS_REPLY'},
	    length  => $ofp->sizeof('ofp_stats_reply') + $ofp->sizeof('ofp_queue_stats'),        # should generate automatically!
	    xid     => 0x00000000
	};

	my $stats_reply_args = {
	    header        => $reply_hdr_args,
	    type          => $enums{'OFPST_QUEUE'},
	    flags          => 0
	};


	my $reply_body_args = {
	    port_no => $port_base,
	    pad         => \@pad_2,
	    queue_id    => 1,
	    tx_bytes     => 0,
	    tx_packets     => 0,
	    tx_errors   => 0
	};

	my $reply_body = $ofp->pack( 'ofp_queue_stats', $reply_body_args);
	my $stats_reply = $ofp->pack( 'ofp_stats_reply', $stats_reply_args ) . $reply_body;

	# Send 'stats_request' message
	print $sock $stats_request;

	# Should add timeout here - will crash if no reply
	my $recvd_mesg;
	sysread( $sock, $recvd_mesg, 1512 ) || die "Failed to receive message: $!";

	# Inspect  message
	if ($recvd_mesg ne $stats_reply) {
	    die "ERROR: stats reply didn't match expected";
	}

	# Send a packet out
	forward_simple($ofp, $sock, $options_ref, 1, 0, 0, 'enqueue');

	# Wait the flow to expire
	sleep 3;

	# Expect increased counters
	$reply_body_args = {
	    port_no => $port_base,
	    pad         => \@pad_2,
	    queue_id    => 1,
	    tx_bytes     => 64,
	    tx_packets     => 1,
	    tx_errors   => 0
	};

	$reply_body = $ofp->pack( 'ofp_queue_stats', $reply_body_args);
	$stats_reply = $ofp->pack( 'ofp_stats_reply', $stats_reply_args ) . $reply_body;


	# Send 'stats_request' message
	print $sock $stats_request;

	# Receive stats reply
	sysread( $sock, $recvd_mesg, 1512 ) || die "Failed to receive message: $!";

	# Inspect  message
	if ($recvd_mesg ne $stats_reply) {
	    die "ERROR: stats reply didn't match expected";
	}
    }

}

run_black_box_test( \&my_test, \@ARGV );

