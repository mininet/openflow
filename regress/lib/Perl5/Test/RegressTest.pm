#!/usr/bin/perl -w

##############################################################################
#
# Script to run regression tests for all projects
# $Id: RegressTest.pm 3864 2008-06-04 07:05:15Z grg $
#
##############################################################################

package Test::RegressTest;

use strict;

use Getopt::Long;
use Test::TeamCity;
use Cwd;
use File::Spec;

use vars qw(@ISA @EXPORT);    # needed cos strict is on

@ISA    = ('Exporter');
@EXPORT = qw(
  &run_regress_test
);

$|++;

# Predeclare my_die
sub my_die;

# Location of project file to test during regressions
my $projectRoot = 'projects';
my $projectFile = 'projects/regress.txt';
my $regressRoot = 'regress';
my $regressFile = 'regress/tests.txt';
my $runFile         = 'run.pl';
my $commonDir   = 'common';
my $globalDir   = 'global';
my $setup       = 'setup';
my $teardown    = 'teardown';

my $_ROOT_DIR   = '';

use constant REQUIRED => 1;
use constant OPTIONAL => 0;

use constant GLOBAL_SETUP    => 'global setup';
use constant GLOBAL_TEARDOWN => 'global teardown';

my $quiet     = 0;
my $svnUpdate = '';
my $help      = '';
my $mapFile;
my @projects;
my $testPath;
my $ci             = '';
my $citest         = '';
my $failfast       = 0;
my $rootOverride   = '';
my $commonSetup    = $setup;
my $commonTeardown = $teardown;
my $commonSTArgs   = '';  
my $controller;
my $listener;
my $portBase = 0;
my $sendDelay;
my $baseIdle;
my $ignoreByteCount;
my $noVlan;
my $noSlicing;
my $noBarrier;
my $noEmerg;
my $lessPorts;

sub run_regress_test {

	my ( $int_handler, @ARGV ) = @_;

	#
	# Process arguments
	#

	unless (
		GetOptions(
			"quiet"             => \$quiet,
			"help"              => \$help,
			"map=s"             => \$mapFile,
			"project=s"         => \@projects,
			"testPath=s"        => \$testPath,
			"ci=s"              => \$ci,
			"citest=s"          => \$citest,
			"failfast"          => \$failfast,
			"common-setup=s"    => \$commonSetup,
			"common-teardown=s" => \$commonTeardown,
			"common-st-args=s"  => \$commonSTArgs,
			"root=s"            => \$rootOverride,
			"controller=s"		=> \$controller,
			"listener=s"		=> \$listener,
			"port_base=s"		=> \$portBase,
			"send_delay=s"		=> \$sendDelay,
			"base_idle=s"		=> \$baseIdle,
			"ignore_byte_count"	=> \$ignoreByteCount,
			"no_vlan"		=> \$noVlan,
			"no_slicing"		=> \$noSlicing,
			"no_barrier"		=> \$noBarrier,
			"no_emerg"		=> \$noEmerg,
			"less_ports"            => \$lessPorts
		)
		and ( $help eq '' )
	  )
	{
		usage();
		exit 1;
	}

	# Catch interupts (SIGINT)
	$SIG{INT} = $int_handler;

	#
	# Check stuff
	#
	
	# If a root override was specified, set it
	if ( $rootOverride ne '' ) {
		$_ROOT_DIR = $rootOverride;
	}
	else {
		my_die( "Unknown root test directory", 0 );
	}
	print "Root directory is $_ROOT_DIR\n";

	# Verify that the continuous integration program is correct if set
	if ( $ci ne '' && $ci ne 'teamcity' ) {
		my_die( "Unknown continuous integration \"$ci\". Supported CI programs: teamcity", 0 );
	}
	if ( $ci ne '' && $citest eq '' ) {
		my_die( "The name of the test was not specified in 'citest'", 0 );
	}
	tcDisableOutput if ( $ci ne 'teamcity' );

	unless ( -w "$_ROOT_DIR/$projectFile" ) {
		my_die("Unable to locate regression test project file $_ROOT_DIR/$projectFile");
	}

	#
	# Verify that the mapfile exists
	#
	if ( defined($mapFile) ) {
		if ( !-f $mapFile ) {
			my_die("Cannot locate map file $mapFile");
		}
		else {
			$mapFile = File::Spec->rel2abs($mapFile);
		}
	}

	my %results;
	my $pass = 1;
	my @failures;

	# Check if a specific test specified on the command line - Jean II
	if ( defined($testPath) ) {

	    my $project;
	    my $regress;
	    my $testDir;
	    my $testFile;
	    my $testPathShort;
	    my @testList;

	    # Split the path into components...
	    ($project, $regress, $testDir, $testFile) = split(/\//,$testPath);

	    if((!defined($project)) || (!defined($regress))) {
		my_die("Invalid testPath $testPath");
	    }

	    # Accept various shorthands, or fully qualified path... Jean II
	    if(!defined($testDir)) {
		#    => project/testdir
		$testPathShort = $regress.'/'.$runFile;
	    } else {
		if(!defined($testFile)) {
		    # Two possible shorthands, try to see which one...
		    if ( -x "$_ROOT_DIR/$projectRoot/$project/$regress/$testDir/$runFile" ) {

			#    => project/regress/testdir
			$testPathShort = $testDir.'/'.$runFile;
		    } else {
			#    => project/testdir/testfile
			$testPathShort = $regress.'/'.$testDir;
		    }
		} else {
		    #    => project/regress/testdir/testfile
		    $testPathShort = $testDir.'/'.$testFile;
		}
	    }
	    push @testList, $testPathShort;

	    # Verify the project
	    push @projects, $project;
	    verifyProjects();

	    # Run the test
	    my ( $result, $tests, $results ) = runAllTests($project, @testList);

	    $pass &= $result;

	    push @failures, $project unless $result;
	    $results{$project} = $results;

	} else {

	    #
	    # Read in the list of projects to test
	    #
	    if ( $#projects == -1 ) {
		readProjects();
	    }
	    verifyProjects();

	    #
	    # Run the regression tests on each project one-by-one
	    #

	    foreach my $project (@projects) {
		my ( $result, $tests, $results ) = runRegressionSuite($project);

		$pass &= $result;

		push @failures, $project unless $result;
		$results{$project} = $results;

		last if ( $failfast && !$result );
	    }
	}

	#
	# Print out any errors if they exist
	#
	if ( !$quiet && !$pass ) {
		print "Regression test suite failed\n";
		print "\n";
		print "Projects failing tests:\n";
		print join( " ", @failures ) . "\n";
		print "\n";
		print "Tests failing within each project\n";
		print "=================================\n";
		foreach my $project (@failures) {
			my @results = @{ $results{$project} };

			print "$project: ";
			for ( my $i = 0 ; $i <= $#results ; $i++ ) {
				my @testSummary = @{ $results[$i] };

				if ( !$testSummary[1] ) {
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
			my @results = @{ $results{$project} };

			for ( my $i = 0 ; $i <= $#results ; $i++ ) {
				my @testSummary = @{ $results[$i] };

				if ( !$testSummary[1] ) {
					my $test = "Project: $project   Test: $testSummary[0]";
					print $test . "\n" . ( '-' x length($test) ) . "\n";
					print "$testSummary[2]";
				}
			}
			print "\n";

		}
	}

}

# int handler was here

#########################################################
sub usage {
	( my $cmd = $0 ) =~ s/.*\///;
	print <<"HERE1";
NAME
   $cmd - run regression tests

SYNOPSIS

   $cmd 
        [--quiet]
        [--map <mapfile>]
        [--project <project>] [--project <project>] ...
	[--testPath <test>]
	[--no_vlan] [--no_slicing] [--no_barrier] [--no_emerg]
        [--ci <test_tool>] [--citest <test_name>]
	[--listener <listener>]
        [--failfast]        
        [--root <root_test_path>]
        [--common-setup <local common setup file name>] 
        [--common-teardown <local common teardown file name>]
        [--common-st-args <args for common setup & teardown>]

   $cmd --help  - show detailed help

HERE1

	return unless ($help);
	print <<"HERE";

DESCRIPTION

   This script runs individual regression tests for each project specified
   in \$ROOT_DIR/projects/regress.txt, unless a list of projects is passed in.
   Within each project, run scripts are executed; each run scripts should
   return 0 for success and non-zero for failure.

OPTIONS

   --quiet
     Run in quiet mode; don't output anything unless there are errors.
   
   --map <mapfile> 
     Remap interfaces per mapfile, which is a list of two interfaces
     per line.
     
   --project <project> ...
     Run specific project(s) instead of those in regress.txt. 

   --testPath <test>
     Run a single test specified by <test>.
     <test> should be of the form:

       black_box/regress/test_hello/run.pl

     or can be shortened by omitting the word "regress" and/or "run.pl":

       black_box/test_hello/run.pl
       black_box/regress/test_hello
       black_box/test_hello

   --no_vlan
     Do not perform any matching on VLAN tags

   --no_slicing
     Do not run slicing tests

   --no_barrier
     Do not run barrier tests

   --no_emerg
     Do not run emergency flow table tests

   --listener <listener>
     Specify port that the switch is listening on
     
   --ci <test_tool> --citest <test_name>
     Unsupported; will enable the use of continuous testing tools like
     TeamCity.  

   --failfast
     Fail fast causes the regression suite to fail as soon as a test
     fails and not to run the teardown scripts.
     
   --root <dir>
     This option is required, and specifies the root directory of all
     projects.
     
   --common-setup <local common setup file name>
     Run a custom setup script for each test.
    
   --common-teardown <local common teardown file name>
     Run a custom teardown script for each test.
     
   --common-st-args <args for common setup & teardown>
     Pass args to setup and teardown.

HERE

}

# Fix color highlithing : '
#########################################################
sub readProjects {
	local $_;

	open PROJFILE, "$_ROOT_DIR/$projectFile"
	  or my_die "Unable to open '$_ROOT_DIR/$projectFile' for reading";

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
		if ( !-d "$_ROOT_DIR/$projectRoot/$project" ) {
			my_die "Cannot locate project '$project'";
		}

		# Verify that the project has a valid regression test description
		if ( !-f "$_ROOT_DIR/$projectRoot/$project/$regressFile" ) {
			my_die
"Cannot locate regression test file '$_ROOT_DIR/$projectRoot/$project/$regressFile' for project '$project'";
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

	#my $msg = "Running tests on project '$project'...\n";
	#print (("=" x length($msg)) . "\n" . $msg) unless $quiet;
	print "Running tests on project '$project'...\n" unless $quiet;

	# Read the tests
	open REGRESSFILE, "$_ROOT_DIR/$projectRoot/$project/$regressFile"
	  or my_die "Unable to open '$_ROOT_DIR/$projectRoot/$project/$regressFile' for reading";

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

	runAllTests( $project, @tests );
}

#########################################################
# runAllTests
#   Run all the tests of a list of tests
sub runAllTests {

	my ( $project, @tests ) = @_;

	my @results;

	# Run the tests one by one
	my %testResults;
	my $pass       = 1;
	my $commonPass = 1;
	my $test;

	$test = $citest . tcGetTestSeparator . 'global.setup';
	tcTestStarted($test);
	print "  Running global setup... " unless $quiet;
	my ( $gsResult, $output ) = runGlobalSetup($project);
	if ( !$gsResult ) {
		$pass = 0;

		# Store the test results for later
		$testResults{GLOBAL_SETUP} = $gsResult;
		my @test_result = ( GLOBAL_SETUP, $gsResult, $output );
		push @results, \@test_result;
	}
	printScriptOutput( $gsResult, $output );
	tcTestFailed( $test, 'Test failed', $output ) if ( !$gsResult );
	tcTestFinished($test);

	if ($gsResult) {
		foreach $test (@tests) {
			my $testStr = $citest . tcGetTestSeparator . $test;
			tcTestStarted($testStr);
			print "  Running test '$test'... " unless $quiet;

			# Common setup
			#print "    common setup\n";
			my ( $csResult, $lsResult, $testResult, $ltResult, $ctResult ) = ( 1, 1, 1, 1, 1 );
			my ( $csOutput, $lsOutput, $testOutput, $ltOutput, $ctOutput );
			( $csResult, $csOutput ) = runCommonSetup($project);
			$testResults{$test} = $csResult;
			$pass       &= $csResult;
			$commonPass &= $csResult;

			# Local setup -- only run if common setup passed
			#print "    local setup\n";
			if ($csResult) {
				( $lsResult, $lsOutput ) = runLocalSetup( $project, $test );
				$testResults{$test} = $lsResult;
				$pass &= $lsResult;
			}

			# Actual test -- only run if both setups succeed
			#print "    actual test\n";
			if ( $csResult && $lsResult ) {
				( $testResult, $testOutput ) = runTest( $project, $test );
				$testResults{$test} = $testResult;
				$pass &= $testResult;
			}

			# Local teardown -- only run if the local setup succeeded
			#print "    local teardown\n";
			if ( $csResult && $lsResult ) {
				( $ltResult, $ltOutput ) = runLocalTeardown( $project, $test );
				$testResults{$test} = $ltResult;
				$pass &= $ltResult;
			}

			# Common teardown -- only run if the common setup succeeded
			#print "    common teardown\n";
			if ($csResult) {
				( $ctResult, $ctOutput ) = runCommonTeardown($project);
				$testResults{$test} = $ctResult;
				$pass       &= $ctResult;
				$commonPass &= $ctResult;
			}

			# Store the test results for later
			$testResult &= $csResult & $lsResult & $ltResult & $ctResult;

			my $output = '';
			$output .= $csOutput   if ( !$csResult );
			$output .= $lsOutput   if ( !$lsResult );
			$output .= $testOutput if ( !$testResult );
			$output .= $ltOutput   if ( !$ltResult );
			$output .= $ctOutput   if ( !$ctResult );

			$output = $testOutput if ($testResult);

			my @test_result = ( $test, $testResult, $output );
			push @results, \@test_result;

			printScriptOutput( $testResult, $output );
			tcTestFailed( $testStr, 'Test failed', $output ) if ( !$testResult );
			tcTestFinished($testStr);

			# Break the tests if the test failed during common setup/teardown
			last if ( !$commonPass );

			# Break the tests if the test failed and we're in failfast mode
			last if ( $failfast && !$testResult );
		}
	}

	# Run the teardown if the global setup passed and
	# the tests passed or we're not doing a failfast
	if ( $gsResult && ( !$failfast || $pass ) ) {
		$test = $citest . tcGetTestSeparator . 'global.teardown';
		tcTestStarted($test);
		print "  Running global teardown... " unless $quiet;
		my ( $result, $output ) = runGlobalTeardown($project);
		if ( !$result ) {
			$pass = 0;

			# Store the test results for later
			$testResults{GLOBAL_TEARDOWN} = $result;
			my @test_result = ( GLOBAL_TEARDOWN, $result, $output );
			push @results, \@test_result;
		}
		printScriptOutput( $result, $output );
		tcTestFailed( $test, 'Test failed', $output ) if ( !$result );
		tcTestFinished($test);
	}

	print "\n\n" unless $quiet;

	# Return the status of the test, plus the various results
	return ( $pass, \@tests, \@results );
}

#########################################################
# runTest
#   Run an individual test from a regression suite
sub runTest {
	my $project = shift;
	my $test    = shift;
    my $args = '';
    
	if ( defined($controller) ) {
		$args .= " --controller=$controller";
	}

	if ( defined($listener) ) {
		$args .= " --listener=$listener";
	}

	if ( defined($portBase) ) {
		$args .= " --port_base=$portBase";
	}

	# Some platforms need bigger delay and bigger base idle - Jean II
	if ( defined($sendDelay) ) {
		$args .= " --send_delay=$sendDelay";
	}
	if ( defined($baseIdle) ) {
		$args .= " --base_idle=$baseIdle";
	}
	# Some platforms can't do byte counts - Jean II
	if ( defined($ignoreByteCount) ) {
		$args .= " --ignore_byte_count";
	}
	# Some setup can not do VLANs - Jean II
	if ( defined($noVlan) ) {
		$args .= " --no_vlan";
	}
	# Some platforms can not do Slicing - Jean II
	if ( defined($noSlicing) ) {
		$args .= " --no_slicing";
	}
	# Some platforms can not do barrier - Jean II
	if ( defined($noBarrier) ) {
		$args .= " --no_barrier";
	}
	# Some platforms can not do emergency flow table
	if ( defined($noEmerg) ) {
		$args .= " --no_emerg";
	}

	# Don't do all ports on some platforms, it's slow and useless...
	if ( defined($lessPorts) ) {
		$args .= " --less_ports";
	}

        if ( defined($commonSTArgs) ) {
                $args .= " --common-st-args=$commonSTArgs";
	}

	if ( -d "$_ROOT_DIR/$projectRoot/$project/$regressRoot/$test" ) {
		return runScript( $project, $test, $runFile, REQUIRED, $args );
	}
	else {
		if ( $test =~ /(.*)\/([^\/]*)/ ) {
			my $dir      = $1;
			my $fileName = $2;
			return runScript( $project, $dir, $fileName, REQUIRED, $args );
		}
		my_die "Error finding test file: $test\n";
	}
}

#########################################################
# runGlobalSetup
#   Run the global setup for a regression suite
sub runGlobalSetup {
	my $project = shift;

	return runScript( $project, $globalDir, $setup, OPTIONAL );
}

#########################################################
# runGlobalTeardown
#   Run the global setup for a regression suite
sub runGlobalTeardown {
	my $project = shift;
	
	return runScript( $project, $globalDir, $teardown, OPTIONAL );
}

#########################################################
# runCommonSetup
#   Run the common setup for a regression suite
sub runCommonSetup {
	my $project = shift;
    my $args = '';

	if ( defined($commonSTArgs) ) {
		$args = " --common-st-args=$commonSTArgs";
		$args = $args . " > /dev/null 2> /dev/null";
	}

	return runScript( $project, $commonDir, $commonSetup, OPTIONAL, $args );
}

#########################################################
# runCommonTeardown
#   Run the common setup for a regression suite
sub runCommonTeardown {
	my $project = shift;
	my $args = '';

	if ( defined($commonSTArgs) ) {
		$args = " --common-st-args=$commonSTArgs";
		$args = $args . " > /dev/null 2> /dev/null";
	}

	return runScript( $project, $commonDir, $commonTeardown, OPTIONAL, $args );
}

#########################################################
# runLocalSetup
#   Run the local setup for a test within the regression suite
sub runLocalSetup {
	my $project = shift;
	my $test    = shift;

	if ( $test =~ /(.*)\/([^\/]*)/ ) {
		my $dir = $1;
		return runScript( $project, $dir, $setup, OPTIONAL );
	}
	else {
		return runScript( $project, $test, $setup, OPTIONAL );
	}
}

#########################################################
# runLocalTeardown
#   Run the local teardown for a test within the regression suite
sub runLocalTeardown {
	my $project = shift;
	my $test    = shift;

	if ( $test =~ /(.*)\/([^\/]*)/ ) {
		my $dir = $1;
		return runScript( $project, $dir, $teardown, OPTIONAL );
	}
	else {
		return runScript( $project, $test, $teardown, OPTIONAL );
	}
}

#########################################################
# runScript
#   Run a test/setup/teardown script rom a regression suite
sub runScript {
	my $project  = shift;
	my $dir      = shift;
	my $script   = shift;
	my $required = shift;
	my $args     = shift || '';

	# Verify that the test exists
	unless ( -x "$_ROOT_DIR/$projectRoot/$project/$regressRoot/$dir/$script" ) {
		if ( $required == REQUIRED ) {
			my_die "Unable to run test '$dir' for project '$project'";
		}
		else {
			return ( 1, "" );
		}
	}

	# Construct the arguments
	#
	# Map file if it exists
	if ( defined($mapFile) ) {
		$args = " --map=$mapFile " . $args;
	}

	# Change to the test directory
	my $origDir = getcwd;
	my $testDir = "$_ROOT_DIR/$projectRoot/$project/$regressRoot/$dir";
	chdir($testDir)
	  or my_die "Unable to change directory to '$regressRoot/$dir'";

	# Run the test
	my $output = `$testDir/$script $args 2>&1`;

	# Change back to the original directory
	chdir($origDir)
	  or my_die "Unable to change directory to '$origDir'";

	if ( $? != 0 ) {
		$output .= "\n\n";
		$output .= "$dir/$script received signal " . ( $? & 127 ) . "\n" if ( $? & 127 );
		$output .= "$dir/$script dumped core\n" if ( $? & 128 );
		$output .= "$dir/$script exited with value " . ( $? >> 8 ) . "\n" if ( $? >> 8 );
	}

	# Return 0 to indicate failure
	return ( $? == 0, $output );
}

#########################################################
# printScriptOutput
#   Print the result of a test script
sub printScriptOutput {
	my ( $result, $output ) = @_;

	if ( !$quiet ) {
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

#########################################################
sub my_die {
	my $mess     = shift @_;
	my $details  = shift @_;
	my $enableTC = shift @_;

	$details  = '' if ( !defined($details) );
	$enableTC = 1  if ( !defined($enableTC) );

	( my $cmd = $0 ) =~ s/.*\///;
	print STDERR "\n$cmd: $mess\n";
	tcTestFailed( $citest, $mess, $details );
	exit 1;
}

1;
