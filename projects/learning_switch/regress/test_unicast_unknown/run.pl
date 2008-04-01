#!/usr/bin/perl -w

use NF2::TestLib;
use NF2::PacketLib;
use OF::OFUtil;
use Error qw(:try);
use IO::Socket;
use strict;

# sending/receiving interfaces - NOT OpenFlow ones
my @interfaces = ("eth5", "eth6", "eth7", "eth8");

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
		
		# Wait for controller to load
		sleep(1);		

		# launch PCAP listenting interface
		nftest_init(\@ARGV,\@interfaces,);
		nftest_start(\@interfaces,);

		my $pkt_args = {
			DA => "00:00:00:00:00:02",
			SA => "00:00:00:00:00:01",
			src_ip => "192.168.0.40",
			dst_ip => "192.168.1.40",
			ttl => 64,
			len => 64
		};
		my $pkt = new NF2::IP_pkt(%$pkt_args);

		save_counters(\%init_counters);

		# send one packet; controller should learn MAC, add a flow 
		#  entry, and send this packet out the other interfaces
		print "Sending now: \n";
		send_and_count('eth5', $pkt->packed, \%delta);
                expect_and_count('eth6', $pkt->packed, \%delta);
                expect_and_count('eth7', $pkt->packed, \%delta);
                expect_and_count('eth8', $pkt->packed, \%delta);

		# sleep as long as needed for the test to finish
		sleep 0.5;

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
