#!/usr/bin/perl -w

##############################################################################
#
# Script to run regression tests for all projects
# $Id: nf21_regress_test.pl 3286 2008-01-30 22:54:54Z grg $
#
##############################################################################

use Getopt::Long;
use NF2::Base;
use NF2::RegAccess;
use Cwd;
use File::Spec;
use strict;

require "reg_defines.ph";

# Location of project file to test during regressions
my $projectRoot = 'projects';
my $projectFile = 'projects/regress.txt';
my $regressRoot = 'regress';
my $regressFile = 'regress/tests.txt';
my $run = 'run';
my $commonDir = 'common';
my $globalDir = 'global';
my $setup = 'setup';
my $teardown = 'teardown';

# check vars are set.
check_NF2_vars_set();

my $_NF2_ROOT       = $ENV{'NF2_ROOT'};
my $_NF2_DESIGN_DIR = $ENV{'NF2_DESIGN_DIR'};
my $_NF2_WORK_DIR   = $ENV{'NF2_WORK_DIR'};

my $_OFT_ROOT	    = $ENV{'OFT_ROOT'};

use constant REQUIRED	=> 1;
use constant OPTIONAL	=> 0;

use constant GLOBAL_SETUP	=> 'global setup';
use constant GLOBAL_TEARDOWN	=> 'global teardown';

#
# Process arguments
#

my $quiet = 0;   # Run in quiet mode -- don't output anything unless
                 # there are errors
my $configs;   	 # Configurations to run be default
my $help = '';
my $svnUpdate = '';
my $mapFile;
my @projects;

unless ( GetOptions ( "configs=s" => \$configs,
		      "quiet" => \$quiet,
		      "svn-update" => \$svnUpdate,
		      "help" => \$help,
		      "map=s" => \$mapFile,
		      "project=s" => \@projects
		    )
	 and ($help eq '')
       ) { usage(); exit 1 }


# Catch interupts (SIGINT)
$SIG{INT} = \&INT_Handler;

#
# Check stuff
#

unless ( -w "$_OFT_ROOT/$projectFile" ) {
  die ("Unable to locate regression test project file $_OFT_ROOT/$projectFile")
}

#
# Verify that the mapfile exists
#
if (defined($mapFile)) {
	if (! -f $mapFile) {
		die ("Cannot locate map file $mapFile");
	}
	else {
		$mapFile = File::Spec->rel2abs($mapFile);
	}
}


#
# Read in the list of projects to test
#

if ($#projects == -1) {
	readProjects();
}
verifyProjects();


#
# Run the regression tests on each project one-by-one
#
my %results;
my $pass = 1;
my @failures;

foreach my $project (@projects) {
	my ($result, $tests, $results) = runRegressionSuite($project);
	$pass &= $result;

	push @failures, $project unless $result;
	$results{$project} = $results;
}


#
# Print out any errors if they exist
#
if ($quiet && !$pass) {
	print "Regression test suite failed\n";
	print "\n";
	print "Projects failing tests:\n";
	print join(" ", @failures) . "\n";
	print "\n";
	print "Tests failing within each project\n";
	print "=================================\n";
	foreach my $project (@failures) {
		my @results = @{$results{$project}};

		print "$project: ";
		for (my $i = 0; $i <= $#results; $i++) {
			my @testSummary = @{$results[$i]};

			if (!$testSummary[1]) {
				print "$testSummary[0] ";
			}
		}
		print "\n";

	}
	print "\n";
	print "\n";
	print "Failing test output\n";
	print "===================\n";

	foreach my $project (@failures) {
		my @results = @{$results{$project}};

		for (my $i = 0; $i <= $#results; $i++) {
			my @testSummary = @{$results[$i]};

			if (!$testSummary[1]) {
				my $test = "Project: $project   Test: $testSummary[0]";
				print $test . "\n" . ('-' x length($test)) . "\n";
				print "$testSummary[2]";
			}
		}
		print "\n";

	}
}

sub INT_Handler {
    	my $signame = shift;

	nf_regwrite('nf2c0', MDIO_0_CONTROL_REG(), 0x8000);
	nf_regwrite('nf2c0', MDIO_1_CONTROL_REG(), 0x8000);
	nf_regwrite('nf2c0', MDIO_2_CONTROL_REG(), 0x8000);
	nf_regwrite('nf2c0', MDIO_3_CONTROL_REG(), 0x8000);

    	print "\nResetting interfaces...\n";
	sleep 5;
    	print "\nExited with SIG$signame\n";

	exit (1);
}

#########################################################
sub usage {
  (my $cmd = $0) =~ s/.*\///;
  print <<"HERE1";
NAME
   $cmd - run the regression tests for the NetFPGA project

SYNOPSIS
   $cmd [--configs <string>]
        [--svn-update]
        [--quiet]
	[--map <mapfile>]
	[--project <project>] [--project <project>] ...

   $cmd --help  - show detailed help

HERE1

  return unless ($help);
  print <<"HERE";

DESCRIPTION

   This script compiles the top level simulation and puts the
   compiled binary, called my_sim, in a specified directory. It then
   looks at all test directories that match in major and minor
   specifications. For each matching test directory that contains an
   executable script called 'run' it copies the contents of the
   source test directory to a work directory and runs that test.

   If you specify a filename then that file should contain a list
   of tests that you want to run. In this case the --major and --minor
   options are ignored. The tests in the file should be only the name
   of the test (without preceding directory information).

   The source verification directory is assumed to contain a directory
   for each test. The name of each test directory is of the form
   test_<major>_<minor> e.g. test_OQM_simple.

   The run script will be invoked with 1 or more: the first argument
   is always the simulator to be used: 'vcs' if Synopsys VCS is used,
   or 'vsim' if Mentor ModelSim is used.
   Additional arguments are:
     'dump' if the --dump option is used
     'gui' if the --gui option is used

   The run script should return 0 for success and non-zero for failure.

   Upon completion the script will put the failing tests into a file
   called FAILED_TESTS (if there are any) placed in the \$NF2_DESIGN_DIR/verif
   directory. This FAILED_TESTS file can be fed back into the command later
   to re-run just those failed tests. To do this just give then name
   FAILED_TESTS as the last argument to the $cmd command.

   The script also generates the include file from the reg_defines.h file
   compiled from a previous simulation of the design. To get the most recent
   register addresses for simulation, first run a simulation with no register
   accesses. This will generate the reg_defines.h file used to get the
   addresses. The next simulation will then get the latest addresses.

OPTIONS
   --major <string>
     Specify the string to match on the first part of the test
     directory name. This is a perl regular expression.
     Default is to match all major tests.

   --minor <string>
     Specify the string to match on the last part of the test
     directory name. This is a perl regular expression.
     Default is to match all minor tests

   --work_verif_dir <dir>
     Specify the directory where the compiled binary should be placed.
     Each test will have its own directory created beneath this directory.
     Default is \$NF2_WORK_DIR/verif.

   --src_verif_dir <dir>
     Specify the directory where the test dirctories are located.
     Each directory should be named test_<major>_<minor> and should contain
     an executable script called 'run' that will perform the actual
     simulation and check the results if necessary.
     Default is \$NF2_DESIGN_DIR/verif.

   --make_file <makefile>
     Specify the makefile to be used to compile the simulation binary.
     By default this is $_NF2_ROOT/lib/Makefiles/sim_makefile

   --make_opt <option_string>
     Specify a single string to be passed to make (e.g. to invoke a different
     make rule).
     Make is invoked by $cmd using: 'make -f <makefile> <option_string>'

   --no_compile
     Specify this if you dont want make to be invoked, but rather just go
     to running the tests. (e.g. you have changed a test but not any verilog)

   --compile_only
     Specify this if you dont want to run any tests, but do want to perform the
     compilation of the verilog simulation.

   --run <run_script>
     The default name for the run script is 'run'. Use this option if you
     want to use a different name for your script.

   --no_update_reg_defines
     Specifies that the simulation should not modify the original reg_defines.h
     file after a run. i.e. the addresses dumped from the simulation will not
     be used in the next run.

   --dump
     Normally the simulation will not produce a VCD file. If you want a
     VCD file then place a file 'dump.v' in your src directory and specify
     this option. Then dump.v will be compiled as a top level module.
     dump.v should be something like this:


      module dump;

      initial
      begin
         #0
            \$dumpfile("testdump.vcd");
            //
            //\$dumpvars;
            \$dumpvars(4,testbench.u_board.unet_top);
            \$dumpon;
            \$display(\$time, " VCD dumping turned on.");

          #4000000 \$finish;

      end

      endmodule

   --gui
     This will run the simulator in an interactive mode (usually with a GUI).

   --vcs
     If this option is present, vcs will run. Otherwise vsim will run.

   --sim_opt <string>
     This option allows the string to be passed to the HDL simulator.
     For example, a macro definition which is checked by the HDL testbench,
     a post-processing option, or a simulation delay model option.

ENVIRONMENT

  The standard NetFPGA2 variables should be set:

  \$NF2_ROOT       - where the root of the NetFPGA2 tree is located
  \$NF2_DESIGN_DIR - the root of your UFPGA tree (with your source
                     files, tests etc)
  \$NF2_WORK_DIR   - a working directory (preferably local disk for speed);


EXAMPLE

   Assume that under \$NF2_DESIGN_DIR/verif are three test directories:

   test_a_1
   test_a_2
   test_b_1

   % $cmd

   will first compile the simulation binary (my_sim) and place it in
   \$NF2_WORK_DIR/verif.

   It will then create subdirectories test_a_1, test_a_2 and
   test_b_1 under test_dir.

   For each of these new directories it will copy all files and
   directories from the source test to the new directory. It will
   then cd to the new directory and call the local run script.

   So, for test_a_1 it will:
   1. create the directory \$NF2_WORK_DIR/test_dir/test_a_1
   2. copy all files and directories from the verif/test_a_1 directory
   3. cd to \$NF2_WORK_DIR/test_dir/test_a_1
   4. run the script \$NF2_WORK_DIR/test_dir/test_a_1/run.

   Assuming tests test_a_2 and test_b_1 failed then they would be
   written to the file FAILED_TESTS. You could then re-run just those
   tests (once you have fixed the problem) by:

   $cmd FAILED_TESTS


SECOND EXAMPLE

   If instead the command was

   % $cmd --major a

   then only the tests test_a_1 and test_a_2 would be run.

   A sample run script is shown below:
HERE

}

#########################################################
sub readProjects {
	local $_;

	open PROJFILE, "$_OFT_ROOT/$projectFile"
		or die "Unable to open '$_OFT_ROOT/$projectFile' for reading";

	# Process each line in the project file
	while (<PROJFILE>) {
		chomp;

		# Remove comments and leading white space
		s/#.*//;
		s/^\s\+//;

		# Skip blank lines
		next if /^$/;

		# Push the project into the list of projects
		push @projects, $_;
	}

	close PROJFILE;
}


#########################################################
# verifyProjects
#   Verify that the specified projects exist and that they contain valid
#   regression test files
sub verifyProjects {
	foreach my $project (@projects) {
		# Verify that the project exists
		if (! -d "$_OFT_ROOT/$projectRoot/$project" ) {
			die "Cannot locate project '$project'";
		}

		# Verify that the project has a valid regression test description
		if (! -f "$_OFT_ROOT/$projectRoot/$project/$regressFile" ) {
			die "Cannot locate regression test file '$_OFT_ROOT/$projectRoot/$project/$regressFile' for project '$project'";
		}
	}
}


#########################################################
# runRegressionSuite
#   Run the regression suite for a particular project
sub runRegressionSuite {
	my $project = shift;
	my @tests;

	local $_;

	my @results;

	#my $msg = "Running tests on project '$project'...\n";
	#print (("=" x length($msg)) . "\n" . $msg) unless $quiet;
	print "Running tests on project '$project'...\n" unless $quiet;

	# Read the tests
	open REGRESSFILE, "$_OFT_ROOT/$projectRoot/$project/$regressFile"
		or die "Unable to open '$_OFT_ROOT/$projectRoot/$project/$regressFile' for reading";

	while (<REGRESSFILE>) {
		chomp;

		# Remove comments and leading/trailing white space
		s/#.*//;
		s/^\s+//;
		s/\s+$//;

		# Skip blank lines
		next if /^$/;

		# Store the test
		push @tests, $_;
	}

	close REGRESSFILE;

	# Run the tests one by one
	my %testResults;
	my $pass = 1;
	my $commonPass = 1;

	print "  Running global setup... " unless $quiet;
	my ($result, $output) = runGlobalSetup($project);
	if (!$result) {
		$pass = 0;

		# Store the test results for later
		$testResults{GLOBAL_SETUP} = $result;
		my @test_result = (GLOBAL_SETUP, $result, $output);
		push @results, \@test_result;
	}
	printScriptOutput($result, $output);

	if ($result) {
		foreach my $test (@tests) {
			print "  Running test '$test'... " unless $quiet;

			# Common setup
			my ($result, $output) = runCommonSetup($project);
			$testResults{$test} = $result;
			$pass &= $result;
			$commonPass &= $result;

			# Local setup
			if ($result) {
				($result, $output) = runLocalSetup($project, $test);
				$testResults{$test} = $result;
				$pass &= $result;
			}


			# Actual test
			if ($result) {
				($result, $output) = runTest($project, $test);
				$testResults{$test} = $result;
				$pass &= $result;
			}

			# Local teardown
			if ($result) {
				($result, $output) = runLocalTeardown($project, $test);
				$testResults{$test} = $result;
				$pass &= $result;
			}

			# Common teardown
			if ($result) {
				($result, $output) = runCommonTeardown($project);
				$testResults{$test} = $result;
				$pass &= $result;
				$commonPass &= $result;
			}

			# Store the test results for later
			my @test_result = ($test, $result, $output);
			push @results, \@test_result;

			printScriptOutput($result, $output);

			# Break the tests if the test failed during common setup/teardown
			last if (!$commonPass);
		}
	}

	if ($result) {
		print "  Running global teardown... " unless $quiet;
		my ($result, $output) = runGlobalTeardown($project);
		if (!$result) {
			$pass = 0;

			# Store the test results for later
			$testResults{GLOBAL_TEARDOWN} = $result;
			my @test_result = (GLOBAL_TEARDOWN, $result, $output);
			push @results, \@test_result;
		}
		printScriptOutput($result, $output);
	}

	print "\n\n" unless $quiet;

	# Return the status of the test, plus the various results
	return ($pass, \@tests, \@results);
}


#########################################################
# runTest
#   Run an individual test from a regression suite
sub runTest {
	my $project = shift;
	my $test = shift;

	if (-d "$_OFT_ROOT/$projectRoot/$project/$regressRoot/$test") {
		return runScript($project, $test, $run, REQUIRED);
	} else {
		if ($test =~ /(.*)\/([^\/]*)/) {
			my $dir = $1;
			my $fileName = $2;
			return runScript($project, $dir, $fileName, REQUIRED);
		}
		die "Error finding test file: $test\n";
	}
}

#########################################################
# runGlobalSetup
#   Run the global setup for a regression suite
sub runGlobalSetup {
	my $project = shift;

	return runScript($project, $globalDir, $setup, OPTIONAL);
}

#########################################################
# runGlobalTeardown
#   Run the global setup for a regression suite
sub runGlobalTeardown {
	my $project = shift;

	return runScript($project, $globalDir, $teardown, OPTIONAL);
}

#########################################################
# runCommonSetup
#   Run the common setup for a regression suite
sub runCommonSetup {
	my $project = shift;

	return runScript($project, $commonDir, $setup, OPTIONAL);
}

#########################################################
# runCommonTeardown
#   Run the common setup for a regression suite
sub runCommonTeardown {
	my $project = shift;

	return runScript($project, $commonDir, $teardown, OPTIONAL);
}

#########################################################
# runLocalSetup
#   Run the local setup for a test within the regression suite
sub runLocalSetup {
	my $project = shift;
	my $test = shift;

	if ($test =~ /(.*)\/([^\/]*)/) {
		my $dir = $1;
		return runScript($project, $dir, $setup, OPTIONAL);
	} else {
		return runScript($project, $test, $setup, OPTIONAL);
	}
}

#########################################################
# runLocalTeardown
#   Run the local teardown for a test within the regression suite
sub runLocalTeardown {
	my $project = shift;
	my $test = shift;

	if ($test =~ /(.*)\/([^\/]*)/) {
		my $dir = $1;
		return runScript($project, $dir, $teardown, OPTIONAL);
	} else {
		return runScript($project, $test, $teardown, OPTIONAL);
	}
}

#########################################################
# runScript
#   Run a test/setup/teardown script rom a regression suite
sub runScript {
	my $project = shift;
	my $dir = shift;
	my $script = shift;
	my $required = shift;

	my $args = '';

	# Verify that the test exists
	unless (-x "$_OFT_ROOT/$projectRoot/$project/$regressRoot/$dir/$script") {
		if ($required == REQUIRED) {
			die "Unable to run test '$dir' for project '$project'";
		}
		else {
			return (1, "");
		}
	}

	# Construct the arguments
	#
	# Map file if it exists
	if (defined($mapFile)) {
		$args .= "--map $mapFile ";
	}

	# Change to the test directory
	my $origDir = getcwd;
	my $testDir = "$_OFT_ROOT/$projectRoot/$project/$regressRoot/$dir";
	chdir($testDir)
		or die "Unable to change directory to '$regressRoot/$dir'";

	# Run the test
	my $output = `$testDir/$script $args 2>&1`;

	# Change back to the original directory
	chdir($origDir)
		or die "Unable to change directory to '$origDir'";

	if ($? != 0) {
		$output .= "\n\n";
		$output .= "$dir/$script received signal " . ($? & 127) . "\n" if ($? & 127);
		$output .= "$dir/$script dumped core\n" if ($? & 128);
		$output .= "$dir/$script exited with value " . ($? >> 8) . "\n" if ($? >> 8);
	}

	# Return 0 to indicate failure
	return ($? == 0, $output);
}

#########################################################
# printScriptOutput
#   Print the result of a test script
sub printScriptOutput {
	my ($result, $output) = @_;

	if (! $quiet) {
		if ($result) {
			print "PASS\n";
		}
		else {
			print "FAIL\n";
			print "Output was:\n";
			print $output;
			print "\n";
		}
	}
}
