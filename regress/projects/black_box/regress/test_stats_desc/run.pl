#!/usr/bin/perl -w
# test_flow_stats

use strict;
use OF::Includes;

sub stats_desc_test {

	my ( $sock, $options_ref ) = @_;

	my $port_base = $$options_ref{'port_base'};

	my $hdr_args = {
		version => get_of_ver(),
		type    => $enums{'OFPT_STATS_REQUEST'},
		length  => $ofp->sizeof('ofp_stats_request') ,        # should generate automatically!
		xid     => 0x00000001
	};

	my $stats_request_args = {
		header        => $hdr_args,
		type          => $enums{'OFPST_DESC'},
		flags		  => 0
	};

	my $stats_request = $ofp->pack( 'ofp_stats_request', $stats_request_args );

	# Send 'stats_request' message
	print $sock $stats_request;

	# Should add timeout here - will crash if no reply
	my $recvd_mesg;
	sysread( $sock, $recvd_mesg, 1512 ) || die "Failed to receive message: $!";

	# Inspect  message
	my $resp_size = length($recvd_mesg);

	my $resp_header = $ofp->unpack( 'ofp_stats_reply', $recvd_mesg );

	#print HexDump ($recvd_mesg);
	print Dumper($resp_header);

	# Verify fields
	verify_header( $resp_header, 'OFPT_STATS_REPLY', $resp_size );

	# Unmarshall embedded description
	my $resp_body = $ofp->unpack('ofp_desc_stats',
		    substr($recvd_mesg, $ofp->offsetof('ofp_stats_reply', 'body')));
	print Dumper($resp_body);
	print "keys: " . join(" ",keys %$resp_body) . "\n";
	my $key;
	foreach $key (sort keys %$resp_body)
	{
		my $val = $resp_body->{$key};
		my $len = scalar(@{$val});
		printf("key=%s ref=%s len=%d val='%s'\n",
			$key,
			ref($val),
			$len,
			pack("c*", @{$val})
			#@{$val}
			);
	}

	#die("forced death");
	die("Missing dp_desc in desc_stats") unless(defined($resp_body->{"dp_desc"}));

}

run_black_box_test( \&stats_desc_test, \@ARGV );

