#!/usr/bin/perl

use Net::MAC::Vendor;
Net::MAC::Vendor::load_cache('oui.txt');

# Quick and dirty for now....
# To make this work run somehting like: ssh -i ~/.ssh/ubiquiti admin@10.0.0.2 'mca-dump' | perl ./switch-info.pl

use JSON;
use Data::Dumper; # Including dumper so you can add things like: print Dumper($data) as debug statements to see what Perl thinks of the JSON data...

# Slurp STDIN, parse as JSON
my $json_text = do { local $/; <STDIN> };
my $json = JSON->new;
my $data = $json->decode($json_text);

# Print our output header - tabs aren't perfect but good enought....
print "Port\tSpeed\t\tPOE\tStatus\t\tMAC\t\t\tIP\t\tVLAN\t\tHostname\n";

my $ports = $data->{port_table};
for my $i (@$ports) {
   my $had_a_device=0;   # Used to keep track of ports with no devices that should still be reported ;; loop local variable

   # This our normal output prefix for a port, we use sprintf to get nice lined up output
   my $prefix = sprintf("%3s/%-3s)@ %-4s : [%-6s/%-5s] %-10s",$i->{port_idx},$i->{media},$i->{speed},$i->{poe_power},$i->{poe_voltage},$i->{stp_state});

   # We get our notion of devices from the MAC table....
   my @devices = @{$i->{mac_table}};
   for my $d (@devices) {
      my $vendorarray = Net::MAC::Vendor::fetch_oui_from_cache( $d->{mac} );
      my $vendorname=@$vendorarray[0];

      printf ("%s\t%14s\t%-24s\t%15s\t%6s%s\n", $prefix,$d->{mac}, $vendorname,$d->{ip},$d->{vlan},$d->{hostname});
      $had_a_device++;
   }
   print "$prefix\n" unless $had_a_device; # Ports without a device still get reported...
}
