#!/usr/bin/perl -W

use strict;
use OF::Includes;
use File::Copy;

# pass to tar only the files we care about; be careful to ignore .svn's
my $release_num = '0.8.1';
my $revision = '2';
my $of_ver = "openflow-test-v$release_num-r$revision";

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

# set x permission for non-.pl files
# originally used perl chmod, but it doesn't work
my @write_perm_list = (
	"./temp/$of_ver/projects/learning_switch/regress/common/setup",
	"./temp/$of_ver/projects/learning_switch/regress/common/teardown",
	"./temp/$of_ver/projects/black_box/regress/common/setup",
	"./temp/$of_ver/projects/black_box/regress/common/teardown"	
);
foreach my $file (@write_perm_list) {
	`chmod 755 $file`;
}

#print $write_perm_list[0] . "\n";

`cd $rootdir/temp; tar czf $of_ver.tar.gz *`;
exit (0);

# DFS 
sub parse_dir {
	my ($path) = @_;
	#print "parse_dir called with $path\n";
	my @file_list;
	# exists?
	if (! -e "$path") { 
		die "checked $path and failed\n"; 
	}
	# file? 
	elsif (-f "$path") { 
		if (file_ok($path)) {
			print "added $path to list\n";
			push @file_list, "$path"; 
			
			copy($path, "temp/$of_ver/$path") || die "failed to copy $path\n";
			
			#for perl files, make them executable 
			my $match = $path =~ m/.pl/;
			print "  match = $match\n";
			if ($match) { 
				# ensure file is executable
				print "  setting chmod for $path\n";
				chmod 755, "temp/$of_ver/$path" || die "failed to set chmod $path\n";
			};
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
