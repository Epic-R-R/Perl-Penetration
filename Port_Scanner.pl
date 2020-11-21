#!/usr/bin/perl

use warnings;
use strict;
use Getopt::Long;
use IO::Socket::INET;
use List::Util 'shuffle';
use Net::Address::IP::Local;
use Net::Pcap;
use Net::RawIP;
use NetPacket::Ethernet;
use NetPacket::ICMP;
use NetPacket::IP;
use NetPacket::TCP;
use NetPacket::UDP;
use POSIX qw/WNOHANG ceil/;
use Pod::Usage;
use Time::HiRes 'sleep';
use Time::Piece;

BEGIN { $SIG{INT} = $SIG{TERM} = sub { exit 0 } }

my $start_time = localtime;
my $VERSION    = 0.3;
my $SOURCE     = 'github.com/Epic-R-R/Perl-Penetration';

GetOptions (
  'delay=f'     => \(my $delay = 1),
  'ip=s'        => \ my $target_ip,
  'range=s'     => \ my $port_range,
  'procs=i'     => \(my $procs = 50),
  'type=s'      => \(my $protocol = 'tcp'),
  'flag=s'      => \ my @flags,
  'verbose'     => \ my $verbose,
  'h|help|?'    => sub { pod2usage(2) },
) or pod2usage(2);

die "Missing --ip parameter, try --help\n" unless $target_ip;

die "ip: $target_ip is not a valid ipv4 address\n"
  unless $target_ip =~ /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/;

die "Must run with root privileges\n" if $> != 0;

die "Unknown protocol type, try tcp or udp\n" unless $protocol =~ /^(?:tcp|udp)$/;

die "flags are for tcp only!\n" if $protocol ne 'tcp' && @flags;
$flags[0] = 'syn' unless @flags || $protocol eq 'udp';
my $flags = { map { $_ => 1 } @flags };
$flags = {} if exists $flags->{null};

my $local_ip = Net::Address::IP::Local->public;

my $local_port = do {
  my $socket = IO::Socket::INET->new(Proto => $protocol, LocalAddr => $local_ip);
  my $socket_port = $socket->sockport();
  $socket->close;
  $socket_port;
};

my %port_directory;
open my $port_file, '<', 'services.txt'
  or die "Error reading services.txt $!\n";
while (<$port_file>)
{
  next if /^#/;
  chomp;
  my ($name, $number_protocol, $probability, $comments) = split /\t/;
  my ($port, $proto) = split /\//, $number_protocol;

  $port_directory{$number_protocol} = {
    port        => $port,
    proto       => $proto,
    name        => $name,
    probability => $probability,
    comments    => $comments,
  };
}

my @ports = shuffle do {
  unless ($port_range)
  {
    map { $port_directory{$_}->{port} }
      grep { $port_directory{$_}->{name} !~ /^unknown$/
             && $port_directory{$_}->{proto} eq $protocol } keys %port_directory;
  }
  else
  {
    my ($min, $max) = $port_range =~ /([0-9]+)-([0-9]+)/
      or die "port-range must be formatted like this: 100-1000\n";
    $min..$max;
  }
};

print "\n$0  Version $VERSION  Source: $SOURCE

$start_time

Starting port scan: type: $protocol, flags: @flags, $procs procs, $delay (secs) delay
Source host: $local_ip:$local_port, target host: $target_ip\n\n";

my $batch_size = ceil(@ports / $procs);

my $default_port_status =
  ($protocol eq 'tcp' && 0 == grep { /^(?:syn|rst|ack)$/ } keys %$flags)
  ? 'open/filtered'
  : 'filtered';

my %port_scan_results = map { $_ => $default_port_status } @ports;
my @child_pids;

for (1..$procs)
{
  my @ports_to_scan = splice @ports, 0, $batch_size;
  my $parent = fork;
  die "unable to fork!\n" unless defined ($parent);

  if ($parent)
  {
    push(@child_pids, $parent);
    next;
  }

  my $continue = 0;
  local $SIG{CONT} = sub { $continue = 1};
  until ($continue) {}

  for my $target_port (@ports_to_scan)
  {
    sleep($delay);
    send_packet($protocol, $target_port, $flags);
  }
  exit 0;
}

my $device_name = pcap_lookupdev(\my $err);
pcap_lookupnet($device_name, \my $net, \my $mask, \$err);
my $pcap = pcap_open_live($device_name, 1024, 0, 1000, \$err);
pcap_compile(
  $pcap,
  \my $filter,
  "(src net $target_ip) && (dst port $local_port)",
  0,
  $mask
);
pcap_setfilter($pcap,$filter);

kill CONT => $_ for @child_pids;

until (waitpid(-1, WNOHANG) == -1) # until all children exit
{
  my $packet_capture = pcap_next_ex($pcap,\my %header,\my $packet);
  if($packet_capture == 1)
  {
    my ($port, $status) = read_packet($packet);
    $port_scan_results{$port} = $status if $port;
  }
  elsif ($packet_capture == -1)
  {
    warn "libpcap errored while reading a packet\n";
  }
}

my $end_time = localtime;
my $duration = $end_time - $start_time;

for (sort { $a <=> $b } keys %port_scan_results)
{
  printf " %5u %-15s %-40s\n", $_, $port_scan_results{$_}, ($port_directory{"$_/$protocol"}->{name} || '')
    if $port_scan_results{$_} =~ /open/ || $verbose;
}

printf "\nScan duration: %u seconds\n%d ports scanned, %d filtered, %d closed, %d open\n\n",
  $duration,
  scalar(keys %port_scan_results),
  scalar(grep { $port_scan_results{$_} eq 'filtered' } keys %port_scan_results),
  scalar(grep { $port_scan_results{$_} eq 'closed'   } keys %port_scan_results),
  scalar(grep { $port_scan_results{$_} =~ /open/     } keys %port_scan_results);

END { pcap_close($pcap) if $pcap }

sub send_packet
{
  my ($protocol, $target_port, $flags) = @_;

  Net::RawIP->new({ ip => {
                      saddr => $local_ip,
                      daddr => $target_ip,
                    },
                    $protocol => {
                      source => $local_port,
                      dest   => $target_port,
                      %$flags,
                    },
                  })->send;
}

sub read_packet
{
  my $raw_data = shift;
  my $ip_data = NetPacket::Ethernet::strip($raw_data);
  my $ip_packet = NetPacket::IP->decode($ip_data);

  if ($ip_packet->{proto} == 6)
  {
    my $tcp = NetPacket::TCP->decode(NetPacket::IP::strip($ip_data));
    my $port = $tcp->{src_port};

    if ($tcp->{flags} & SYN)
    {
      return ($port, 'open');
    }
    elsif ($tcp->{flags} & RST)
    {
      return ($port, 'closed');
    }
    return ($port, 'unknown');
  }
  elsif ($ip_packet->{proto} == 17)
  {
    my $udp = NetPacket::UDP->decode(NetPacket::IP::strip($ip_data));
    my $port = $udp->{src_port};
    return ($port, 'open');
  }
  else
  {
    warn "Received unknown packet protocol: $ip_packet->{proto}\n";
  }
}

__END__

=head1 NAME

port_scanner - a tool for scan tcp/udp port

=head1 SYNOPSIS

port_scanner [options]

 Options:
  --ip,     -i   ip address to scan e.g. 10.30.1.52
  --type    -t   type of protocol to use either tcp or udp (defaults to tcp)
  --flag    -f   flag to set on tcp (defaults to SYN, use "null" for no flags)
  --range,  -r   range of ports to scan e.g. 10-857 (search named ports if range not provided)
  --delay,  -d   seconds to delay each packet send per process. Can be decimal (e.g. 0.5)
  --help,   -h   display this help text
  --verbose,-v   verbose mode, print closed and filtered ports
  --procs,  -p   how many concurrent packets to send at a time (defaults to 1)

=head2 Examples

Search all the named ports on host C<216.58.208.78>

  sudo perl Port_Scanner -i 216.58.208.78

Search a defined range of ports on host C<216.58.208.78>

  sudo perl Port_Scanner --ip 216.58.208.78 --range 1-1450

=head3 Request frequency

C<port_scanner> can make concurrent requests, use the C<procs> and C<delay> to fine tune the request frequency you need.

Make 50 requests every 0.25 seconds print all results

  sudo perl Port_Scanner --ip 216.58.208.78  --delay 0.25 --procs 50 --verbose

Same thing, with abbreviated parameters

  sudo perl Port_Scanner -i 216.58.208.78 -d 0.25 -p 50 -v

=head3 Types of scans

Perform a TCP SYN scan (default)

  sudo perl Port_Scanner -i 216.58.208.78 -f syn

TCP FIN scan

  sudo perl Port_Scanner -i 216.58.208.78 -f fin

UDP scan

  sudo perl Port_Scanner -i 216.58.208.78 -t udp

TCP XMAS Scan

  sudo perl Port_Scanner -i 216.58.208.78 -f fin -f psh -f urg

TCP null scan

  sudo perl Port_Scanner -i 216.58.208.78 -f null

=cut
