#!/usr/bin/perl -w
# test_hello

use strict;
use IO::Socket;
use Data::HexDump;
use Data::Dumper;

use NF2::TestLib;
use NF2::PacketLib;
use OF::OFUtil;
use OF::OFPacketLib;

sub my_test {
	
	my ($sock) = @_;

	# hello sequence automatically done by test harness!		
}

run_black_box_test(\&my_test);
