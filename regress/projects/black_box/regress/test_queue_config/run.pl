#!/usr/bin/perl -w
# test_queue_config

use strict;
use OF::Includes;

sub my_test {

    my ( $sock, $options_ref ) = @_;

    if ( not defined( $$options_ref{'no_slicing'} ) ) {
	my $port_base = $$options_ref{'port_base'};
	my $num_ports = $$options_ref{'num_ports'};
        
	# for each port,

	for (my $i = 1; $i <= $num_ports; $i++){

	    my $hdr_args = {
		version => get_of_ver(),
		type    => $enums{'OFPT_QUEUE_GET_CONFIG_REQUEST'},
		length  => $ofp->sizeof('ofp_queue_get_config_request'), # should generate automatically!
		xid     => 0x00000000
	    };
        
	    my @pad_2 = (0,0);
	    my $queue_request_args = {
		header        => $hdr_args,
		port      => $i,
		pad       => \@pad_2
	    };
        
	    my $queue_request = $ofp->pack( 'ofp_queue_get_config_request', $queue_request_args );
        
	    # Send 'stats_request' message
	    print $sock $queue_request;
        
	    # Should add timeout here - will crash if no reply
	    my $recvd_mesg;
	    sysread( $sock, $recvd_mesg, 1512 ) || die "Failed to receive message: $!";
        
	    my $msg = $ofp->unpack( 'ofp_queue_get_config_reply', $recvd_mesg );
        
	    my $msg_size      = length($recvd_mesg);
	    # Verify fields
	    verify_header( $msg, 'OFPT_QUEUE_GET_CONFIG_REPLY', $msg_size );
	}
    }
}

run_black_box_test( \&my_test, \@ARGV );

