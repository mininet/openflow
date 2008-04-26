#!/usr/bin/perl -w

use Getopt::Long;
use NF2::TestLib;
use NF2::PacketLib;
use OF::OFUtil;
use Error qw(:try);
use IO::Socket;
use strict;

my $mapFile;
# Process command line options
unless ( GetOptions ("map=s" => \$mapFile,)) { 
	usage(); 
	exit 1;
}

if (defined($mapFile)) {
        nftest_process_iface_map($mapFile);
}

# sending/receiving interfaces - NOT OpenFlow ones
my @interfaces = ("eth1", "eth2", "eth3", "eth4");

my (%init_counters, %final_counters, %delta);

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
		
		# Wait for contorller to load
		sleep(1);		

		# launch PCAP listenting interface
		nftest_init(\@ARGV,\@interfaces,);
		nftest_start(\@interfaces,);

		my $pkt_args = {
			DA => "00:00:00:00:00:01",
			SA => "00:00:00:00:00:01",
			src_ip => "192.168.0.40",
			dst_ip => "192.168.0.40",
			ttl => 64,
			len => 64
		};
		my $pkt = new NF2::IP_pkt(%$pkt_args);

		save_counters(\%init_counters);

		# send one packet; controller should learn MAC, add a flow 
		#  entry, and send this packet out the other interfaces
		print "Sending now: \n";
		send_and_count(nftest_get_iface('eth1'), $pkt->packed, \%delta);


		my $pkt_args = {
			DA => "00:00:00:00:00:02",
			SA => "00:00:00:00:00:02",
			src_ip => "192.168.1.40",
			dst_ip => "192.168.1.40",
			ttl => 64,
			len => 64
		};
		my $pkt = new NF2::IP_pkt(%$pkt_args);
		send_and_count(nftest_get_iface('eth2'), $pkt->packed, \%delta);
		
		my $pkt_args = {
			DA => "00:00:00:00:00:03",
			SA => "00:00:00:00:00:03",
			src_ip => "192.168.2.40",
			dst_ip => "192.168.2.40",
			ttl => 64,
			len => 64
		};
		my $pkt = new NF2::IP_pkt(%$pkt_args);
		send_and_count(nftest_get_iface('eth3'), $pkt->packed, \%delta);
		
		my $pkt_args = {
			DA => "00:00:00:00:00:04",
			SA => "00:00:00:00:00:04",
			src_ip => "192.168.3.40",
			dst_ip => "192.168.3.40",
			ttl => 64,
			len => 64
		};
		my $pkt = new NF2::IP_pkt(%$pkt_args);
		send_and_count(nftest_get_iface('eth4'), $pkt->packed, \%delta);

		#print "about to nftest_finish()\n";
		my $unmatched_hoh = nftest_finish();

		print "Checking pkt errors\n";
		my $total_errors = nftest_print_errors($unmatched_hoh);

		# check counter values 
		save_counters(\%final_counters);
		$total_errors += verify_counters(%init_counters, %final_counters, %delta);		

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
