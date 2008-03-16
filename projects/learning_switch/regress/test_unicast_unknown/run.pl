#!/usr/bin/perl -w

use NF2::TestLib;
use NF2::PacketLib;
#new additions
use Error qw(:try);
use IO::Socket;
use strict;

use constant NUM_PKTS => 20;

my (%rx_init, %rx_final, %rx_pkts);
my (%tx_init, %tx_final, %tx_pkts);

# sending/receiving interfaces - NOT OpenFlow ones
my @interfaces = ("eth6", "eth7", "eth8", "eth9");

# check that we're root?
#      if ($EUID == 0) {
# eventually should add byte counters

my %counters;

sub trim($)
{
        my $string = shift;
        $string =~ s/^\s+//;
        $string =~ s/\s+$//;
        return $string;
}

sub get_if_rx {
	my $interface = shift; 
	return `/sbin/ifconfig $interface | grep \'RX packets:\' | awk \'{print \$2}\' | awk -F : \'{print \$2}\'`;  
}

sub get_if_tx {
	my $interface = shift;
        return `/sbin/ifconfig $interface | grep \'TX packets:\' | awk \'{print \$2}\' | awk -F : \'{print \$2}\'`;
}

sub my_send {
	my($interface, $pkt) = @_;
	nftest_send($interface, $pkt);
	$tx_pkts{$interface}++;
	my $len = length $pkt;
	print "length of sent packet = $len\n";
}

sub my_expect {
        my($interface, $pkt) = @_;
        nftest_expect($interface, $pkt);
        $rx_pkts{$interface}++;
}

sub save_init_counters {
	foreach my $i (@interfaces) {
		$rx_init{$i} = get_if_rx($i);
		$tx_init{$i} = get_if_tx($i);
		$rx_pkts{$i} = 0;
		$tx_pkts{$i} = 0;
	}
	#my $test = $rx_before{'eth6'};
	#print "rx_before = $test\n";
}

sub save_final_counters {
        foreach my $i (@interfaces) {
                $rx_final{$i} = get_if_rx($i);
                $tx_final{$i} = get_if_tx($i);
        }
}

sub verify_counters {
	my $errors = 0;
        foreach my $i (@interfaces) {
                if ($rx_init{$i} + $rx_pkts{$i} != $rx_final{$i}) {
			$errors++;
			print "rx_init + rx_pkts != rx_final for interface $i, please fix\n";
		}
		if ($tx_init{$i} + $tx_pkts{$i} != $tx_final{$i}) {
                	$errors++;
                        print "tx_init + tx_pkts != tx_final for interface $i, please fix\n";
		}
        }
	return $errors;
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
		print "added controller...\n";
		
		# Wait for router to initialize
		sleep(1);		

		# launch PCAP listenting interface
		nftest_init(\@ARGV,\@interfaces,);
		nftest_start(\@interfaces,);

		my $testerMAC0 = "00:ca:fe:00:00:01";
		my $testerMAC1 = "00:ca:fe:00:00:02";

		my $testerIP0 = "192.168.0.40";
		my $testerIP1 = "192.168.1.40";

		# set parameters
		my $DA = $testerMAC1;
		my $SA = $testerMAC0;
		my $TTL = 64;
		my $DST_IP = $testerIP1;
		my $SRC_IP = $testerIP0;;
		my $len = 64;

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

                # below may be cleaner way of defining it
		#my $pkt = nftest_send_IP('192.168.0.100', '192.168.1.100', len => 100);

		save_init_counters();
		
		# send one packet; controller should learn MAC, add a flow 
		#  entry, and send this packet out the other interfaces
		print "Sending now: \n";
		my_send('eth6', $pkt);
		my_expect('eth7', $pkt);
		my_expect('eth8', $pkt);
		my_expect('eth9', $pkt);

		# sleep as long as needed for the test to finish
		sleep 1;

		#print "about to nftest_finish()\n";
		my $unmatched_hoh = nftest_finish();

		print "Checking pkt errors\n";
		my $total_errors = nftest_print_errors($unmatched_hoh);

		# check counter values 
		save_final_counters();
		$total_errors += verify_counters();		

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

                # Ensure controller killed even if we have an error
                kill 9, $pid;

		# Remove OF kernel module
		`killof.pl`;

		my $of_kmod_loaded = `lsmod | grep openflow_mod`;
		if (trim($of_kmod_loaded) eq "") {
		#  print "successfully removed kernel module\n";

		}
		else {
			die "failed to remove kernel module... please fix!\n";
		}

		#verify controller removal
		# need to clear output from controller removal first
		#my $clear_output = `ps -A | grep controller`;
		#print "clear_output = $clear_output\n";
		# this strategy isn't working...
		my $controller_removed = `ps -A | grep controller`;
		print "controller_removed = $controller_removed!\n";
		# commented-out temporarily until above issue fixed
		#if (trim($controller_removed) ne "") { die "failed to remove controller\n"; } 

                # Exit with the resulting exit code
                exit($exitCode);
        };
}


