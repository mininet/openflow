#!/usr/bin/perl -W

use strict;
use OF::Includes;
use File::Copy;

# pass to tar only the files we care about; be careful to ignore .svn's
my $release_num = '0.5.1';
my $of_ver = "openflow-tests-v$release_num";

if (! -d "temp") { mkdir "temp"; }
if (! -d "temp/$of_ver") { mkdir "temp/$of_ver"; }

# set alternate release num
my $numArgs = $#ARGV + 1;
if ($numArgs > 0) { $release_num = $ARGV[0]; }

check_OF_vars_set();

my $rootdir = $ENV{'OFT_ROOT'};
print "starting at root dir $rootdir\n";
chdir $rootdir;

my @ignore_list = (
	'./temp',
	'./scripts/copy_NF2_code.sh',
	'./scripts/make_release.pl',
	'./projects/learning_switch/regress/test_forward_bandwidth/run.pl',
	'./projects/learning_switch/regress/test_forward_bandwidth/run.pl',
	'./projects/black_box/regress/test_send_bandwidth_fixed/run.pl',
	'./projects/black_box/regress/test_send_bandwidth_random/run.pl',
	'./projects/black_box/regress/test_add_flow_bandwidth/run.pl',
	'./projects/black_box/regress/test_add_flow_latency/run.pl',
	'./projects/black_box/regress/test_receive_bandwidth_fixed/run.pl',
	'./projects/black_box/regress/test_receive_bandwidth_random/run.pl',
	'./projects/black_box/regress/test_forward_bandwidth_fixed/run.pl',
	'./projects/black_box/regress/test_forward_bandwidth_random/run.pl',
	'./projects/black_box/regress/test_forward_latency/run.pl',
	'./projects/black_box/regress/test_switch_bandwidth_random/run.pl',
	'./projects/black_box/regress/test_switch_bandwidth_random/run.pl'
);

my @files = parse_dir ('.');

print "\n";

foreach my $file (@files) {
  print $file . "\n";
}

my @files_appended;
foreach my $file (@files) {
	push @files_appended, "$file";
}

my $files_separated = join (' ', @files_appended);
#print $files_separated, "\n";

#print `cd .. && pwd`;

#`tar czf temp/$of_ver.tgz $files_separated`;
`tar czf temp/$of_ver.tgz temp`;
exit (0);

# DFS 
sub parse_dir {
	my ($path) = @_;
	print "parse_dir called with $path\n";
	my @file_list;
	# exists?
	if (! -e "$path") { 
		die "checked $path and failed\n"; 
	}
	# file? 
	elsif (-f "$path") { 
		if (file_ok($path)) {
			#print "added $path to list\n";
			push @file_list, "$path"; 
			
			copy($path, "temp/$of_ver/$path") || die "failed to copy $path\n";
		}
		else {
			#print "ignore file $path\n";
		}
	}
	# directory?
	elsif (-d $path) {
		#print "parsing directory $path\n";
		opendir(DIR, $path) || print "Can't open... maybe try chmod 777";
		my @files_in_dir=readdir(DIR);
		closedir(DIR);
		
		if (dir_ok('', $path) && $path ne '.') {
			#remove ./ at beginning
			
			my $path_temp = substr($path, 2);
			mkdir("temp/$of_ver/$path_temp") || die "failed to make path temp/$of_ver/$path_temp\n";
		}
		
		#print " dir looks like: \n";
		foreach my $file (@files_in_dir) {
			#print "   " . $file . "\n";
		}
		 
		foreach my $subdir (@files_in_dir) {
			if (dir_ok($subdir, $path) ) {
				#print "\nabout to parse $path/$subdir\n";
				push @file_list, parse_dir("$path/$subdir");
			}
		}
	}
	else {
		die ("unknown error");
	}

	return @file_list;
}

sub dir_ok {
	my ($subdir, $path) = @_;	
	my $ignore = 0;
	foreach my $file (@ignore_list) {
		if ("$path/$subdir" eq $file) { $ignore = 1; last; }
	}
	
	# ignore these three regardless of path - other require path to ignore
	if ($subdir ne '.' && $subdir ne '..' && $subdir ne '.svn' && !$ignore ) {
		return 1;
	}
	else {
		return 0;
	}
}

sub file_ok {
	my ($path) = @_;	
	my $ok = 1;
	foreach my $file (@ignore_list) {
		if ("$path" eq $file) { $ok = 0; last; }
	}
	return $ok;	
}