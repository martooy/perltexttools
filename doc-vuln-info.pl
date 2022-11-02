#!/usr/bin/perl

my $debug=0;

use Term::ANSIColor qw(:constants);
my %outputcolors = (
    Headers => BRIGHT_WHITE,
    Critical => BRIGHT_MAGENTA,
    High => BRIGHT_RED,
    Medium => BRIGHT_YELLOW,
    Low => GREEN,
    Informational => BLUE);

my %vulncount = (Critical => 0, High => 0, Medium => 0, Low => 0, Informational => 0);
my @vulnlist; 

# Build a printf format string based on some fixed guessed fieldwidths
my @fieldwidths = (70,15,25,25);
my $format = join(' ', map { "%-${_}s" } @fieldwidths) . "\n";

while (<>) {
	s#\r##;
	chop;
	
	# TOC Vulnerability entry
	if (m#([HMLI])(\d+)\.\t(.*)\t\d+$#) {
		my %vuln = ( 'severity' => $1, 'num' => $2, 'title' => $3);
		$vuln{id} = $vuln{severity} . $vuln{num}; 
		$vuln{risk} = 'High' if $vuln{severity} =~ /H/;
		$vuln{risk} = 'Medium' if $vuln{severity} =~ /M/i;
		$vuln{risk} = 'Low' if $vuln{severity} =~ /L/i;
		$vuln{risk} = 'Informational' if $vuln{severity} =~ /I/i;
		$vulncount{$vuln{risk}}++;
		push @vulnlist, \%vuln;
		print "Foundone $vuln{title}\n" if ($debug);
	}

	# Finding in the body
	if ((! m#\t\d+$#) && (m#^([CHMLI])(\d+)\.(.*)#)) {
		print "Body match: $3\n" if ($debug);
		my $id = $1 . $2;
		# Go look for other fields until we hit a Summary: line
		#
		while (<>) {
			s#\r##;
			if (m#(Criticality|Component|Category):\s*(.*)#) {
				$bodyvuln{$id}{$1} = $2;
				print "Setting $id $1 to $2\n" if ($debug);
			}
			last if (m#Summary:#); 
		}
	}
}

##################
## Report Output
##################
print $outputcolors{Headers}, "###########\n## Fixed width output\n###########\n";

print $outputcolors{Headers}, sprintf $format, "Issue","Risk","Component","Category";
for my $i (@vulnlist) {
print $outputcolors{$i->{risk}}, sprintf $format, 
       $i->{title},
       $i->{risk},
       $bodyvuln{$i->{id}}{Component},
       $bodyvuln{$i->{id}}{Category}  ;
}
print "\n";

print $outputcolors{Headers}, "###########\n## Tab separated output\n###########\n";
print $outputcolors{Headers}, join("\t",("Issue","Risk","Component","Category")) . "\n";
for my $i (@vulnlist) {
    print $outputcolors{$i->{risk}},  join("\t",
       $i->{title},
       $i->{risk},
       $bodyvuln{$i->{id}}{Component},
       $bodyvuln{$i->{id}}{Category}) . "\n";
}
print "\n";

print $outputcolors{Headers}, "###########\n## Vuln Counts\n###########\n";
for $i ('Critical','High','Medium','Low','Informational') {
    print  BOLD BLUE "$vulncount{$i} findings that are $i\n";
}
