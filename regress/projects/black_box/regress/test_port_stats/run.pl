#!/usr/bin/perl -w
# test_port_stats

use strict;
use OF::Includes;

sub forward_any {

	forward_simple(@_, 'any');
}

sub my_test {

	my ( $sock, $options_ref ) = @_;

	enable_flow_expirations( $ofp, $sock );

	my $port_base = $$options_ref{'port_base'};
	my $num_ports = $$options_ref{'num_ports'};
		
	# for each port, 

	my $hdr_args = {
		version => get_of_ver(),
		type    => $enums{'OFPT_STATS_REQUEST'},
		length  => $ofp->sizeof('ofp_stats_request'),        # should generate automatically!
		xid     => 0x00000000
	};

	my $stats_request_args = {
		header        => $hdr_args,
		type          => $enums{'OFPST_PORT'},
		flags		  => 0
	};

	my $stats_request = $ofp->pack( 'ofp_stats_request', $stats_request_args );

	my $reply_hdr_args = {
		version => get_of_ver(),
		type    => $enums{'OFPT_STATS_REPLY'},
		length  => $ofp->sizeof('ofp_stats_reply'),        # should generate automatically!
		xid     => 0x00000000
	};

	my $stats_reply_args = {
		header        => $reply_hdr_args,
		type          => $enums{'OFPST_PORT'},
		flags		  => 0
	};
	
#	my $match_args = {
#		wildcards => 0x3ff,
#		in_port   => 0,
#		dl_src    => 0,
#		dl_dst    => 0,
#		dl_vlan   => 0,
#		dl_type   => 0,
#		nw_src    => 0,
#		nw_dst    => 0,
#		nw_proto  => 0,
#		tp_src    => 0,
#		tp_dst    => 0
#	};

	my $reply_body;
	for (my $i = $port_base; $i < $port_base + $num_ports; $i++ ) {
		my $body_args = {
			port_no     => $port_base,
			rx_count 	=> 0,
			tx_count 	=> 0,
			drop_count  => 0	
		};	
		$reply_body .= $ofp->pack( 'ofp_port_stats', $body_args);
	}

	my $stats_reply = $ofp->pack( 'ofp_stats_reply', $stats_reply_args ) . $reply_body;
	
	# Send 'stats_request' message
	print $sock $stats_request;

	# Should add timeout here - will crash if no reply
	my $recvd_mesg;
	sysread( $sock, $recvd_mesg, 1512 ) || die "Failed to receive message: $!";

	# Inspect  message
	my $msg_size      = length($recvd_mesg);
	my $expected_size = $ofp->sizeof( 'ofp_stats_reply' ) + 4 * $ofp->sizeof('ofp_port_stats');
	
	# removed this compare because varying numbers of ports may be activated
	#compare( "msg size", $msg_size, '==', $expected_size );

	my $msg = $ofp->unpack( 'ofp_stats_reply', $recvd_mesg );

	#print HexDump ($recvd_mesg);
	#print Dumper($msg);

	# Verify fields
	verify_header( $msg, 'OFPT_STATS_REPLY', $msg_size );

	compare( "type", $$msg{'type'}, '==', $enums{'OFPST_PORT'} );
	compare( "flags", $$msg{'flags'}, '==', 0);

#	if ($recvd_mesg ne $stats_reply) {
#		die "stats reply is not what was expected"
#	}

	# TODO: Look at each received port_stats field, to ensure they equal zero...

	# Send packets
	for_all_port_pairs( $ofp, $sock, $options_ref, \&forward_any, 0x3ff);
	
	# TODO: Look at each received port_stats field, to ensure correct counters
	
	# Send 'stats_request' message
	print $sock $stats_request;

	# Should add timeout here - will crash if no reply
	my $recvd_mesg;
	sysread( $sock, $recvd_mesg, 1512 ) || die "Failed to receive message: $!";		
}

run_black_box_test( \&my_test, \@ARGV );

