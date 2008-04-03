#!/usr/bin/perl -w

use strict;
use IO::Socket;
use Error qw(:try);
use Data::HexDump;
use Data::Dumper;

use NF2::TestLib;
use NF2::PacketLib;
use OF::OFUtil;
use OF::OFPacketLib;

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

my $control_hello_args = { 
	header => $hdr_args,
	version => 50, # arbitrary, not sure what this should be
	flags => 0,
	miss_send_len => 0xffff
};
my $control_hello = $ofp->pack('ofp_control_hello', $control_hello_args);

my $sock = new IO::Socket::INET (
        LocalHost => 'localhost',
        LocalPort => '975',
        Proto => 'tcp',
        Listen => 1,
        Reuse => 1
);
die "Could not create socket: $!\n" unless $sock;

my $pid;
# Fork off the "controller" server
if ( !( $pid = fork ) ) {

	# Wait for controller to setup socket 
	sleep 1;

	# Spawn secchan process
	exec "secchan", "nl:0", "tcp:127.0.0.1";
	die "Failed to launch secchan: $!";
}
else {
	# Wait for secchan to connect
	my $new_sock = $sock->accept();
	
	# Send 'control_hello' message
	print $new_sock $control_hello;

	my $recvd_mesg;
	sysread($new_sock, $recvd_mesg, 1512) || die "Failed to receive message: $!";
	
	# Kill secchan process
	`killall secchan`;

	# Inspect  message
	my $msg_size = length($recvd_mesg);
	my $expected_size = $ofp->sizeof('ofp_data_hello');
	if ($msg_size < $expected_size) {
		die "Wrong mesg size: $msg_size, expected $expected_size\n";
	}

	my $msg = $ofp->unpack('ofp_data_hello', $recvd_mesg);
	#print HexDump ($recvd_mesg);
	print Dumper($msg);

	# Verify fields
	expect("header version", $$msg{'header'}{'version'}, 1);
	expect("header type", $$msg{'header'}{'type'}, OFPT_DATA_HELLO);
	expect("header length", $$msg{'header'}{'length'}, $msg_size);

	close($sock);

	print "SUCCESS!\n";
	exit 0;
}
