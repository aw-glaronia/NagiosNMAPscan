#!/usr/bin/perl -w
####
#	Author:		Serg Belokamen <serg@fuzzyit.com>
#	Author:		Zhivko Todorov <ztodorov@neterra.net> - add feature to pass custom arguments to nmap
#	Author:		Andreas Walker <a.walker@glaronia.ch> - add feature for resolving Hostnames (quick n'dirty). Removed some translation glitches. Added perf-data output.
#	Date:		10-Apr-2019
#	Version:	0.0.6
#	License:	GPL
####

use strict;
use Getopt::Long;
# Needed for resolving Hostnames
use Socket;


# Nagios parsable return codes
use constant OK       => 0;
use constant WARNING  => 1;
use constant CRITICAL => 2;
use constant UNKNOWN  => 3;

MAIN:
{
	# Values for variable below will be collected from CLI
	my $nmap_path     = undef(); # Path to Nmap
	my $scan_hostname = undef(); # Hostname to Resolve
	my $scan_address  = undef(); # IP to scan
	my $allowed_ports = undef(); # Allowed ports
	my $cust_args     = ''; # User defined Nmap arguments
	my $help          = undef(); # Ask for usage info.

	# Store Nmap output here.
	my @nmap_raw = (); # Raw Nmap output
	my @allowed  = (); # Allowed port list
	my @opened   = (); # Opened not-allowed ports
	my @total    = (); # All listening ports
	my @closed   = (); # Allowed closed ports

	# Receive command line parameters.
	GetOptions
	(
		"ip=s"    	=> \$scan_address,
		"fqdn=s"	=> \$scan_hostname,
		"nmap=s"  	=> \$nmap_path,
		"ports=s" 	=> \$allowed_ports,
		"cust_args=s" 	=> \$cust_args,
		"help"    	=> \$help
	);

	# Show usage info.	
	if($help) { showHelp(); exit(OK); }
	
	# Resolve Hostname, if supplied, and store it to $scan_address
	if ($scan_hostname)
	{
		$scan_address = inet_ntoa(inet_aton($scan_hostname));
	}

	# Parse command line arguments.
	if(!parseCLIArgs($scan_address, $nmap_path, $allowed_ports))
	{
		print "Invalid command line arguments supplied.";
		showHelp();
		exit(UNKNOWN);
	}

	# Parse supplied port list.
	@allowed = sort(extractPortList($allowed_ports));

	# All ports should be blocked
	$allowed_ports = "none" if(scalar @allowed == 0);

	# Check that supplied ports were parsed correctly
	if($allowed[0] and $allowed[0] == -1)
	{
		print "Port number(s) supplied are invalid.";
		exit(UNKNOWN);
	}

	# Start nmap scan.
	####
	# Security update:
	# Patch submitted by: Erik Strahl <beamerik@gmx.net>
	# This tells nmap to scan all ports from 1 to 65535 and not just often 
	# utilized ports, which is the nmap default setting.
	#
	# Old: @nmap_raw = `$nmap_path -P0 $scan_address`;
	####
	@nmap_raw = `$nmap_path $cust_args $scan_address`;

	# Parse nmap scan results.
	for(my $i = 0; $i < scalar @nmap_raw; $i++)
	{
		# Clean output
		chomp $nmap_raw[$i];

		# Extract and store port numbers from scan output
		push(@total, $1)
			if($nmap_raw[$i] =~ /^(\d{1,})\/(tcp|udp).*$/);
	}

	# Sort open ports array
	@total  = sort(@total);
	@opened = @total;

	# Check if ONLY (all of the) allowed ports were found - OK
	if(join("", @opened) eq join("", @allowed))
	{
		# Print Nagios OK message
		print "OK, ";
		print "IP: ".$scan_address."; ";
		print "Scanned: ".$allowed_ports."; ";
		print "Allowed: ".$allowed_ports;
		print "|open=".$scan_address.;

		# Return OK to Nagios parser
		exit(OK);
	}

	for(my $i = 0; $i < scalar @allowed; $i++)
	{
		my $found = 0;

		for(my $j = 0; $j < scalar @opened; $j++)
		{
			if($allowed[$i] eq $opened[$j])
			{
				$opened[$j] = $opened[scalar @opened- 1];
				pop(@opened);
				$found = 1;
			}
		}

		push(@closed, "-".$allowed[$i])
			if($found == 0);
	}

	map($_ = "+".$_, @opened);

	my $t_exit  = UNKNOWN;
	my $t_output = undef();

	if(scalar @closed > 0) { $t_exit = WARNING;  $t_output = "WARNING, ";  }
	if(scalar @opened > 0) { $t_exit = CRITICAL; $t_output = "CRITICAL, "; }

	print $t_output.
			"IP: ".$scan_address."; ".
			"Result: ".join(",", @opened, @closed, )."; ".
			"Scanned: ".join(",", @total)."; ".
			"Allowed: ".$allowed_ports;
			"|open=".join(",", @total).;

	exit($t_exit);

} # END MAIN


sub parseCLIArgs
{
	my ($scan_address,	$nmap_path, $allowed_ports) = @_;

	# Make sure that Nmap is executable...
	return 0
		if(!$nmap_path or !-x $nmap_path);

	# Check for syntatically valid IP address
	return 0
		if($scan_address !~ /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/);

	# Check if port list was supplied
	return 0 
		if(!$allowed_ports);

	return 1;
} # END sub parseCLIArgs


sub extractPortList
{
	my ($ports) = @_;
	my @ports   = ();

	my $port_min   = 0;
	my $port_max   = 65534;
	my $empty_list = "e";

	chomp($ports);

	@ports = split(/,/, $ports);

	# Validate port numbers
	for(my $i= 0; $i < scalar @ports; $i++)
	{
		return ()
			if($ports[$i] eq $empty_list);

		$ports[0] = -1
			if($ports[$i] !~ /^\d{1,}$/ or
				($ports[$i] > $port_max or $ports[$i] < $port_min));
	}

	return @ports;
} # END sub extractPortList


sub showHelp
{
	my @showHelpMsg =
	(
		"USAGE:",
		"    -n --nmap      /path/to/nmap.",
		"    -i --ip        IP address to scan.",
		"    -f --fqdn      Hostname to Scan.",
		"    -p --ports     Comma sepparated list of allowd ports or 'e' (empty).",
		"    -c --cust_args Custom arguments to be passed to nmap.",
		"    -h --help      Display help message (this).",
		"",
		"DEFINITIONS:",
		"    OK",
		"    Nothing change, allowed ports list matches scanned ports list.",
		"",
		"    CRITICAL",
		"    Allowed ports list does not match scanned ports list. Additional",
		"    ports were found to be listening. They are denoted by a '+' sign",
		"    infront of them in the 'Result' string.",
		"",
		"    WARNING",
		"    Allowed ports list does not match scanned ports list. Some of ",
		"    the ports in 'Allowed' string were found to be closed. They are",
		"    are denoted by a '-' sign infront of them in the 'Result'",
		"    string.",
		"",
		"NOTE:",
		"    To define an empty port (--port) list use a value of e (e). For",
		"    example '--ports e'",
		"",
		"    If CRITICAL AND WARNING states are one then CRITICAL will be",
		"    displayed. However, WARNING results can be destinguished from ",
		"    CRITICAL since they will have a '-' prefix (CRITICAL will have",
		"    a '+' prefix).",
		"",
		"USAGE EXAMPLES:",
		"    Alowed ports are NULL:",
		"    script -n /usr/bin/nmap -i 192.168.1.1 -p e",
		"",
		"    Use Hostname (FQDN) as target:",
		"    script -n /usr/bin/nmap -f host.domain.tld -p e",
		"",
		"    More regular usage (allowed port is SSH: 22 and HTTP: 445):",
		"    script -n /usr/bin/nmap -i 192.168.1.1 -p 22,445",
		"",
		"    More usage (allowed port is SSH: 22 and HTTP: 445)",
		"    and port range 40000-45000 is excluded from scanning:",
		"    script -n /usr/bin/nmap -i 192.168.1.1 -p 22,445 -c '--exclude-ports 40000-45000'",
		"",
		"    By default nmap scans only 1000 most common used ports!!!",
		"    Please consider what type of scan you need!!!",
		""
	);

	print join("\n", @showHelpMsg);
} # END sub showHelp
