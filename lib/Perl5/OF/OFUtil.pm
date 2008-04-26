#############################################################
# $Id: OFUtil.pm 3161 2007-12-13 21:08:05Z bdh $
#
# Module provides basic functions for use by OF Perl scripts.
#
# Revisions:
#
##############################################################
 
package OF::OFUtil; 

use Getopt::Long;
use NF2::TestLib;
use Error qw(:try);
use OF::OFPacketLib;
use Exporter;

@ISA = ('Exporter');
@EXPORT = qw( 
	&trim 
	&send_and_count 
	&expect_and_count 
	&save_counters 
	&verify_counters 
	&setup_kmod 
	&teardown_kmod
	&compare
	&createControllerSocket
	&run_learning_switch_test
	&do_hello_sequence
	&run_black_box_test 
);

my $nf2_kernel_module_path = 'datapath_nf2/linux-2.6'; 
my $nf2_kernel_module_name = 'openflow_hw_nf2.ko';

# sending/receiving interfaces - NOT OpenFlow ones
my @interfaces = ( "eth1", "eth2", "eth3", "eth4" );

##############################################################
#
# Check that the user has set up their environment correctly.
#
##############################################################
sub trim($) {
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

sub send_and_count {
	my($interface, $pkt, $counters) = @_;
        nftest_send($interface, $pkt);
        $$counters{$interface}{tx_pkts}++;
}

sub expect_and_count {
        my($interface, $pkt, $counters) = @_;
        nftest_expect($interface, $pkt);
        $$counters{$interface}{rx_pkts}++;
}

sub save_counters {
        my $counters = @_;
	foreach my $i (keys %counters) {
                $$counters{$i}{rx_pkts} = get_if_rx($i);
                $$counters{$i}{tx_pkts} = get_if_tx($i);
        }
}

sub verify_counters {
	my (%c1, %c2, %delta);
        my $errors = 0;
        foreach my $i (keys %c1) {
                if ($c1{$i}{rx_pkts} + $delta{$i}{rx_pkts} != $c2{$i}{rx_pkts}) {
                        $errors++;
                        print "rx_pkts comparison failed for interface $i, please fix\n";
                }
                if ($c1{$i}{tx_pkts} + $delta{$i}{tx_pkts} != $c2{$i}{tx_pkts}) {
		        $errors++;
                        print "tx_init + tx_pkts != tx_final for interface $i, please fix\n";
                }
        }
        return $errors;
}

sub setup_kmod {
	my $isNF2 = shift;
	
        # ensure all interfaces use an address
        for (my $i = 1; $i <= 4; $i++) {
        	my $iface = nftest_get_iface("eth$i");
                `/sbin/ifconfig $iface 192.168.$i.1`;
        }

        # verify kernel module not loaded
        my $of_kmod_loaded = `lsmod | grep openflow`;
        if ($of_kmod_loaded ne "") {
        	print "$of_kmod_loaded\n";
            print "openflow kernel module already loaded... please fix!\n";
            exit 1;
        }
        
        # verify controller not already running
        my $controller_loaded = `ps -A | grep controller`;
        if ($controller_loaded ne "") {
            print "controller already loaded... please remove and try again!\n";
            exit 1;
        }

        my $openflow_dir=$ENV{OF_ROOT};

        # create openflow switch on four ports
        `insmod ${openflow_dir}/datapath/linux-2.6/openflow_mod.ko`;
		
		# If we are using the NetFPGA add the hardware kernel module
		if ($isNF2) {
	        `insmod ${openflow_dir}/${nf2_kernel_module_path}/${nf2_kernel_module_name}`;
		}
        `dpctl adddp 0`;

        for (my $i = 5; $i <= 8; $i++) {
        	my $iface = nftest_get_iface("eth$i");
            `dpctl addif 0 $iface`;
        }
}

sub teardown_kmod {
	my $isNF2 = shift;

	# check that we're root?
	my $who = `whoami`;
	if (trim($who) ne 'root') { die "must be root\n"; }
	
	# check if openflow kernel module loaded
	my $of_kmod_loaded = `lsmod | grep openflow_mod`;
	if ($of_kmod_loaded eq "") { die "nothing to do, exiting\n"; } 
	
	print "tearing down interfaces and datapaths\n";
	
	# remove interfaces from openflow
	for (my $i = 5; $i <= 8; $i++) {
		my $iface = nftest_get_iface("eth$i");
		`dpctl delif 0 $iface`;
	}

	`dpctl deldp 0`;
	
	# tear down the NF2 module if necessary
	if ($isNF2) {
		my $of_hw_kmod_removed = `rmmod ${nf2_kernel_module_name}`;
		if ($of_hw_kmod_removed ne "") {
			die "failed to remove hardware kernel module... please fix!\n";
		}
	}

	my $of_kmod_removed = `rmmod openflow_mod`;
	if ($of_kmod_removed ne "") {
		die "failed to remove kernel module... please fix!\n";
	}
	
	$of_kmod_loaded = `lsmod | grep openflow_mod`;
	if ($of_kmod_loaded ne "") {
		die "failed to remove kernel module... please fix!\n";
	}

	exit 0;
}

sub compare {
	my ($test, $val, $op, $expected) = @_;
	my $success = eval "$val $op $expected" ? 1 : 0;
	if (!$success) { die "$test: error $val not $op $expected\n"; }
}

sub createControllerSocket {
	my ($host) = @_;
	my $sock = new IO::Socket::INET ( 
 		LocalHost => $host,
        	LocalPort => '975',
        	Proto => 'tcp',
        	Listen => 1,
        	Reuse => 1
	);
	die "Could not create socket: $!\n" unless $sock;
	return $sock;
}

sub process_command_line() {
	my %options = ();
	GetOptions(\%options);
	
	# Process the mappings if specified
	if (defined($options{'map'})) {
		nftest_process_iface_map($options{'map'});
	}
	
	return %options;
}

sub run_learning_switch_test {
	my %options = process_command_line();

	# test is a function pointer
	my ($test) = @_;

	my $mapFile;

	# Process command line options
	unless ( GetOptions( "map=s" => \$mapFile, ) ) {
		usage();
		exit 1;
	}

	if ( defined($mapFile) ) {
		nftest_process_iface_map($mapFile);
	}

	my ( %init_counters, %final_counters, %delta );

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

			# Wait for controller to load
			sleep(1);

			# Launch PCAP listenting interface
			nftest_init( \@ARGV, \@interfaces, );
			nftest_start( \@interfaces, );

			save_counters( \%init_counters );

			# Run test
			my %delta = &$test();

			# sleep as long as needed for the test to finish
			sleep 0.5;
		
			# check counter values
			save_counters( \%final_counters );
			my $total_errors = verify_counters( %init_counters, %final_counters, %delta );

			#print "about to nftest_finish()\n";
			my $unmatched = nftest_finish();

			print "Checking pkt errors\n";
			$total_errors += nftest_print_errors($unmatched);

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

			# Exit with the resulting exit code
			exit($exitCode);
		  };
	}
}

sub do_hello_sequence {
	
	my ($ofp, $sock) = @_;
	
	my $hdr_args_control = {
		version => 1,
		type    => $enums{'OFPT_CONTROL_HELLO'},
		length  => 16,                             # should generate automatically!
		xid     => 0x00000000
	};
	my $control_hello_args = {
		header        => $hdr_args_control,
		version       => 1,                # arbitrary, not sure what this should be
		flags         => 1,                # ensure flow expiration sent!
		miss_send_len => 0x0080
	};
	my $control_hello = $ofp->pack( 'ofp_control_hello', $control_hello_args );

	# Send 'control_hello' message
	print $sock $control_hello;

	my $recvd_mesg;
	sysread( $sock, $recvd_mesg, 1512 ) || die "Failed to receive message: $!";
	#print "received message after control hello\n";
	
	# Inspect  message
	my $msg_size = length($recvd_mesg);
	my $expected_size = $ofp->sizeof('ofp_data_hello') + 4 * $ofp->sizeof('ofp_phy_port');
	# should probably account for the expected 4 ports' info
	compare ("msg size", length($recvd_mesg), '==', $expected_size);

	my $msg = $ofp->unpack('ofp_data_hello', $recvd_mesg);
	#print HexDump ($recvd_mesg);
	#print Dumper($msg);

	# Verify fields
	compare("header version", $$msg{'header'}{'version'}, '==', 1);
	compare("header type", $$msg{'header'}{'type'}, '==', $enums{'OFPT_DATA_HELLO'});
	compare("header length", $$msg{'header'}{'length'}, '==', $msg_size);
}

sub run_black_box_test {
	my %options = process_command_line();
	
	# test is a function pointer
	my ($test) = @_;
	
	my $sock = createControllerSocket('localhost');
	
	my $pid;
	
	my $total_errors = 1;
	
	# Fork off the "controller" server
	if ( !( $pid = fork ) ) {
	
		# Wait for controller to setup socket
		sleep .1;
	
		# Spawn secchan process
		exec "secchan", "nl:0", "tcp:127.0.0.1";
		die "Failed to launch secchan: $!";
	}
	else {
		my $exitCode = 1;
		try {
	
			# Wait for secchan to connect
			my $new_sock = $sock->accept();		
	
			# Launch PCAP listenting interface
			nftest_init( \@ARGV, \@interfaces, );
			nftest_start( \@interfaces, );
	
			#if ($ofp) { print "ofp not null\n"; } else { print "ofp null\n"; }
			do_hello_sequence($ofp, $new_sock);
	
			&$test($new_sock, %options);
		}
		catch Error with {
	
			# Catch and print any errors that occurred during control processing
			my $ex = shift;
			if ($ex) {
				print $ex->stringify();
			}
		}
		finally {
	
			# Sleep as long as needed for the test to finish
			sleep 0.5;
	
			close($sock);
	
			# Kill secchan process
			`killall secchan`;
			
			my $unmatched = nftest_finish();
			print "Checking pkt errors\n";
			$total_errors = nftest_print_errors($unmatched); 
	
			my $exitCode;
			if ( $total_errors == 0 ) {
				print "SUCCESS!\n";
				$exitCode = 0;
			}
			else {
				print "FAIL: $total_errors errors\n";
				$exitCode = 1;
			}
			
			exit($exitCode);
		};
	}
}

# Always end library in 1
1;
