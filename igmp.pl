#! /usr/bin/perl -w


# Based on https://code.google.com/archive/p/perl-igmp-querier/
# Added some arguments et al 
# Call is e.g.
# querier.pl eth0 192.168.1.102 60
# will send every 60 second a igmp record query
# 13:28:17.311326 IP 192.168.10.2 > 224.0.0.1: igmp query v2

use strict;
use POSIX;
use Socket;
use Proc::Daemon;
use Proc::PID::File;

my $dst = "224.0.0.1";
my ( $sourceInterface, $sourceAddress, $igmpInterval ) = @ARGV;

if ( not defined $sourceInterface ) {
    die "Need souce interface name as first argument, e.g. eth0\n";
}

if ( not defined $sourceAddress ) {
    die "Need souce ip address as second argument, e.g. 192.168.1.3\n";
}

if ( not defined $igmpInterval ) {
    die
      "Need interval as third argument to send igmp query, e.g. 30 (seconds)\n";
}

print "Starting IGMP Querier\n";
my $daemon = 1;

if ( $daemon == 1 ) {

    # Daemonize
    print "Running as a daemon\n";
    Proc::Daemon::Init();

    # If already running, then exit
    if ( Proc::PID::File->running() ) { exit(0); }
}

socket( RAW, AF_INET, SOCK_RAW, 255 ) || die $!;
setsockopt( RAW, 0, 1, 1 );
setsockopt( RAW, SOL_SOCKET, 25, pack( "Z*", $sourceInterface ) );

my $src_host = ( gethostbyname($sourceAddress) )[4];
my $dst_host = ( gethostbyname($dst) )[4];
my ($packet) = forgepkt( $src_host, $dst_host );
my ($dest) = pack( 'Sna4x8', AF_INET, 0, $dst_host );

# Enter loop to send IGMP Queries
for ( ; ; ) {
    send( RAW, $packet, 0, $dest );
    if ( $daemon != 1 ) { print "Sent IGMP Query.\n"; }
    sleep $igmpInterval;

}

sub forgepkt {

    my $src_host = shift;
    my $dst_host = shift;

    my $zero_cksum = 0;
    my $igmp_proto = 2;
    my $igmp_type  = '11';
    my $igmp_mrt   = '64';
    my $igmp_pay   = 0;
    my $igmp_chk   = 0;
    my $igmp_len   = 0;

    my ($igmp_pseudo) =
      pack( 'H2H2vN', $igmp_type, $igmp_mrt, $igmp_chk, $igmp_pay );

    $igmp_chk = &checksum($igmp_pseudo);

    $igmp_pseudo =
      pack( 'H2H2vN', $igmp_type, $igmp_mrt, $igmp_chk, $igmp_pay );

    $igmp_len = length($igmp_pseudo);

    my $ip_ver       = 4;
    my $ip_len       = 6;
    my $ip_ver_len   = $ip_ver . $ip_len;
    my $ip_tos       = 00;
    my ($ip_tot_len) = $igmp_len + 20 + 4;
    my $ip_frag_id   = 11243;
    my $ip_frag_flag = "010";
    my $ip_frag_oset = "0000000000000";
    my $ip_fl_fr     = $ip_frag_flag . $ip_frag_oset;
    my $ip_ttl       = 1;
    my $ip_opts      = '94040000';                      # router alert

    my ($head) = pack( 'H2H2nnB16C2n',
        $ip_ver_len, $ip_tos, $ip_tot_len, $ip_frag_id,
        $ip_fl_fr,   $ip_ttl, $igmp_proto );

    my ($addresses) = pack( 'a4a4', $src_host, $dst_host );

    my ($pkt) = pack( 'a*a*H8a*', $head, $addresses, $ip_opts, $igmp_pseudo );
    return $pkt;
}

sub checksum {
    my ($msg) = @_;
    my ( $len_msg, $num_short, $short, $chk );
    $len_msg   = length($msg);
    $num_short = $len_msg / 2;
    $chk       = 0;
    foreach $short ( unpack( "S$num_short", $msg ) ) {
        $chk += $short;
    }
    $chk += unpack( "C", substr( $msg, $len_msg - 1, 1 ) ) if $len_msg % 2;
    $chk = ( $chk >> 16 ) + ( $chk & 0xffff );
    return ( ~( ( $chk >> 16 ) + $chk ) & 0xffff );
}
