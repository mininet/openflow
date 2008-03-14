#!/usr/bin/perl -w

use NF2::TestLib;
use NF2::PacketLib;
#new additions
use Error qw(:try);
use IO::Socket;
use strict;

use constant NUM_PKTS => 20;

# check that we're root?
#      # Work out whether we're running as root or not. Root can bind to a
#      # network interface -- non-root users have to bind to the address
#      # corresponding to the device.
#      if ($EUID == 0) {
#         # Set the necessary options on the socket to bind it to the device
#         setsockopt($fh, SOL_SOCKET, SO_BINDTODEVICE, pack('Z*', $device))
#            or die "Unable to set socket option SO_BINDTODEVICE on device '$device'";
#      }

sub trim($)
{
        my $string = shift;
        $string =~ s/^\s+//;
        $string =~ s/\s+$//;
        return $string;
}

my $OPENFLOW_DIR='~/openflow-v0.1.7';

# Move to SCONE's root directory
#chdir '../../sw' or die "Can't cd: $!\n";

# Setup OF kernel module with interfaces
setup();

my $pid;

# Fork off a process for controller
if ( !( $pid = fork ) ) {

        # Run controller from this process
        exec "controller", "-v", "nl:0";
        die "Failed to launch controller: $!";
}
else {
        my $exitCode = 1;
        try {
		# Run control from this process
		print "adding controller...\n";
		
		# Wait for router to initialize
		sleep(1);		

		# sending/receiving interfaces - NOT OpenFlow ones
		my @interfaces = ("eth6", "eth7", "eth8", "eth9");
		nftest_init(\@ARGV,\@interfaces,);
		nftest_start(\@interfaces,);

		my $testerMAC0 = "00:ca:fe:00:00:01";
		my $testerMAC1 = "00:ca:fe:00:00:02";
		my $testerMAC2 = "00:ca:fe:00:00:03";
		my $testerMAC3 = "00:ca:fe:00:00:04";

		my $testerIP0 = "192.168.0.40";
		my $testerIP1 = "192.168.1.40";
		my $testerIP2 = "192.168.2.40";
		my $testerIP3 = "192.168.3.40";

		# set parameters
		my $DA = $testerMAC1;
		my $SA = $testerMAC0;
		my $TTL = 64;
		my $DST_IP = $testerIP1;
		my $SRC_IP = $testerIP0;;
		my $len = 64;

		#my $nextHopMAC = "dd:55:dd:66:dd:77";

		# create mac header
		my $MAC_hdr = NF2::Ethernet_hdr->new(DA => $DA,
				SA => $SA,
				Ethertype => 0x800
				);

		#create IP header
		my $IP_hdr = NF2::IP_hdr->new(ttl => $TTL,
				src_ip => $SRC_IP,
				dst_ip => $DST_IP
				);

		$IP_hdr->checksum(0);  # make sure its zero before we calculate it.
			$IP_hdr->checksum($IP_hdr->calc_checksum);

		# create packet filling.... (IP PDU)         
		my $PDU = NF2::PDU->new($len - $MAC_hdr->length_in_bytes() - $IP_hdr->length_in_bytes() ); 

		my $pkt = $MAC_hdr->packed . $IP_hdr->packed . $PDU->packed;

		my @totalPktLengths = (0, 0, 0, 0);

		print "Sending now: \n";

                # Send a packet
                #my $pkt = nftest_send_IP('192.168.0.100', '192.168.1.100', len => 100);

		nftest_send('eth6', $pkt);
		nftest_expect('eth7', $pkt);
		nftest_expect('eth8', $pkt);
		nftest_expect('eth9', $pkt);

		print "\n";

		sleep 2;

		#print "about to nftest_finish()\n";
		my $unmatched_hoh = nftest_finish();

		print "Checking pkt errors\n";
		my $total_errors = nftest_print_errors($unmatched_hoh);

		# check counter values from ifconfig?


                if ( $total_errors == 0 ) {
                        print "SUCCESS!\n";
                        $exitCode = 0;
                }
                else {
                        print "FAIL: $total_errors errors\n";
                        $exitCode = 1;
                }

        }
        catch Error with {

                # Catch and print any errors that occurred during control processing
                my $ex = shift;
                if ($ex) {
                        print $ex->stringify();
                }
        }
        finally {

                # Ensure SCONE is killed even if we have an error
                kill 9, $pid;

		# remove controller and OF kernel module
		`killall controller`;
		`killof.pl`;

		my $of_kmod_loaded = `lsmod | grep openflow_mod`;
		if (trim($of_kmod_loaded) eq "") {
		#  print "successfully removed kernel module\n";

		}
		else {
			die "failed to remove kernel module... please fix!\n";

		}

		#verify controller removal
		my $controller_removed = `ps -A | grep controller`;
		if (trim($controller_removed) ne "") { die "failed to remove controller\n"; } 

                # Exit with the resulting exit code
                exit($exitCode);
        };
}


sub setup {
	# verify kernel module not loaded
	my $of_kmod_loaded = `lsmod | grep openflow_mod`;
	if ($of_kmod_loaded eq "") {
		print "loading kernel module\n";
	}
	else {
		print "openflow kernel module already loaded... please fix!\n";
		exit 1;
	}

	# verify controller not already running 
	my $controller_loaded = `ps -A | grep controller`;
	if ($controller_loaded eq "") {
		# controller not loaded, good
	}
	else {
		print "controller already loaded... please remove and try again!\n";
		exit 1;
	}

	# create openflow switch on four ports
	`insmod ~/openflow-v0.1.7/datapath/linux-2.6/openflow_mod.ko`;
	`dpctl adddp 0`;
	`dpctl addif 0 eth2`;
	`dpctl addif 0 eth3`;
	`dpctl addif 0 eth4`;
	`dpctl addif 0 eth5`;
}
