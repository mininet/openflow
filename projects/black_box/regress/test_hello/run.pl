#!/usr/bin/perl -w

use IO::Socket;
#use Data::HexDump;
#require 'openflow.ph';
use NF2::TestLib;
use NF2::PacketLib;
use OF::OFUtil;
use OF::OFPacketLib;
use Error qw(:try);
use IO::Socket;
use Data::Dumper;
use strict;

# REMOVE and replace with read-in constants from C code
use constant OFPFC_ADD => 0;
use constant OFPAT_OUTPUT => 0;
use constant OFPT_CONTROL_HELLO => 0;
use constant OFPT_DATA_HELLO => 1;

my $hdr_args = {
        version => 1,
        type => OFPT_CONTROL_HELLO,
        length => 16, # need to replace later
        xid => 0x0000abcd
};
#my $hdr = &ofp->pack('ofp_header', $hdr_args);

my $control_hello_args = { 
	header => $hdr_args,
	version => 50, # arbitrary, not sure what this should be
	flags => 0,
	miss_send_len => 0xffff
};
my $control_hello = &ofp->pack('ofp_control_hello', $control_hello_args);

#print HexDump($control_hello);

my $sock = new IO::Socket::INET (
        LocalHost => 'localhost',
        LocalPort => '975',
        Proto => 'tcp',
        Listen => 1,
        Reuse => 1
);
die "Could not create socket: $!\n" unless $sock;

# is this necessary?
$sock->autoflush(1);

my $pid;

# Fork off the controller server
if ( !( $pid = fork ) ) {

	# wait for controller to setup socket 
	sleep 1;

	# spawn secchan process
	exec "secchan", "nl:0", "tcp:127.0.0.1";
	die "Failed to launch secchan: $!";
}
else {
	# wait for secchan to connect
	my $new_sock = $sock->accept();
	
	# Send 'control_hello' message
	print $new_sock $control_hello;

	my $recvd_mesg;
	if (sysread($new_sock, $recvd_mesg, 1512)) {
		#print HexDump($recvd_mesg);
	}
	else {
		die "Failed to receive message: $!";
	}
	
	# Kill secchan process
	`killall secchan`;

	# Inspect 'data_hello' message
	#print HexDump ($recvd_mesg);
	my $msg_size = length($recvd_mesg);
	my $expected_size = &ofp->sizeof('ofp_data_hello');
	if ($msg_size < $expected_size) {
		die "Wrong mesg size: $msg_size, expected $expected_size\n";
	}

	my $msg = &ofp->unpack('ofp_data_hello', $recvd_mesg);
	print Dumper($msg);

	# Verify header version
	my $header_version = $$msg{'header'}{'version'};
	if ($header_version != 1) {
		die "Wrong header version: $header_version, expected 1\n";
	}

	# Verify type
	my $header_type = $$msg{'header'}{'version'};
	if ($header_type != OFPT_DATA_HELLO) {
		die "Wrong header type: $header_type, expected ".OFPT_DATA_HELLO." \n";
	}

	# Verify size of packet matches
	my $header_length = $$msg{'header'}{'length'};
	if ($msg_size != $header_length) {
		die "Wrong header length: $header_length, expected $msg_size\n";
	} 

	close($sock);

	print "SUCCESS!\n";
	exit 0;
}
