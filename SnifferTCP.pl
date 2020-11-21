#!/usr/bin/perl

use autodie;
use strict;
use warnings;
use Socket ':all';
use NetPacket::IP;

my $port_tcp = getservbyname('echo', 'tcp');
my %protocol_map = qw(1 ICMP 6 TCP 17 UDP);

socket(my $sniffer, AF_INET, SOCK_RAW, IPPROTO_ICMP);
setsockopt($sniffer,    IPPROTO_IP, IP_HDRINCL, 1);
bind($sniffer, pack_sockaddr_in($port_tcp, INADDR_ANY));

while(1){
    if(recv($sniffer, my $received_bytes, 65565, 0)){
        my $ip = NetPacket::IP->decode($received_bytes);
        printf "Protocol %s %s -> %s\n",
        ($protocol_map{ $ip->{proto} or 'Unknow'}),
        $ip->{src_ip},
        $ip->{dest_ip};
    }
}