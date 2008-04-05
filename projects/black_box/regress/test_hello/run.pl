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

my $hdr_args = {
        version => 1,
        type => $enums{'OFPT_CONTROL_HELLO'},
        length => 16, # should generate automatically!
        xid => 0x0000abcd
};

my $control_hello_args = { 
	header => $hdr_args,
	version => 50, # arbitrary, not sure what this should be
	flags => 0,
	miss_send_len => 0xffff
};
my $control_hello = $ofp->pack('ofp_control_hello', $control_hello_args);

my $sock = OF::OFUtil::createControllerSocket('localhost');

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
	my $expected_size = $ofp->sizeof('ofp_data_hello') + 4 * $ofp->sizeof('ofp_phy_port');
	# should probably account for the expected 4 ports' info
	compare ("msg size", length($recvd_mesg), '==', $expected_size);

	my $msg = $ofp->unpack('ofp_data_hello', $recvd_mesg);
	#print HexDump ($recvd_mesg);
	print Dumper($msg);

	# Verify fields
	compare("header version", $$msg{'header'}{'version'}, '==', 1);
	compare("header type", $$msg{'header'}{'type'}, '==', $enums{'OFPT_DATA_HELLO'});
	compare("header length", $$msg{'header'}{'length'}, '==', $msg_size);

	close($sock);

	print "SUCCESS!\n";
	exit 0;
}
