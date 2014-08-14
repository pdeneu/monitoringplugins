#!/usr/bin/perl -w

# COPYRIGHT:
#
# This software is Copyright (c) 2014 GNE GmbH, Philipp Deneu
#                                <support@gne.de>
#
# (Except where explicitly superseded by other copyright notices)
#
#
# LICENSE:
#
# This work is made available to you under the terms of Version 2 of
# the GNU General Public License. A copy of that license should have
# been provided with this software, but in any event can be snarfed
# from http://www.fsf.org.
#
# This work is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301 or visit their web page on the internet at
# http://www.fsf.org.
#
#
# CONTRIBUTION SUBMISSION POLICY:
#
# (The following paragraph is not intended to limit the rights granted
# to you to modify and distribute this software under the terms of
# the GNU General Public License and is only of importance to you if
# you choose to contribute your changes and enhancements to the
# community by submitting them to GNE GmbH.)
#
# By intentionally submitting any modifications, corrections or
# derivatives to this work, or any other work intended for use with
# this Software, to GNE GmbH, you confirm that
# you are the copyright holder for those contributions and you grant
# GNE GmbH a nonexclusive, worldwide, irrevocable,
# royalty-free, perpetual, license to use, copy, create derivative
# works based on those contributions, and sublicense and distribute
# those contributions and any derivatives thereof.
#
# Nagios and the Nagios logo are registered trademarks of Ethan Galstad.

=head1 NAME

check_groupwise.pl - Plugin to monitor GroupWise MTA, POA and GWIA

=head1 SYNOPSIS

check_groupwise.pl
     -H <groupwise-server>
     [-S] 
     [-u <user>]
     [-p <password]
     [-P <port>]
     -m <mode>
     -l <command>
     [-w <warning>]
     [-c <critical>]
    [-V]
    [-h]

Plugin to monitor GroupWise MTA, POA and GWIA

=head1 OPTIONS

=over

=item -H|--hostname

GroupWise Server Hostname or IP-Address

=item -S|--ssl

To use secure HTTPS connection

=item -u|--user

User for Agent HTTP Interface

=item -p|--password

Password for Agent HTTP Interface

=item -m|--mode

Type of agent to monitor: mta, poa, gwia

=item -P|--port

Port 

=item -l|--command

Command for specified agent:

 - MTA:
 \- info
    - process and version info
 \- links
    - status of mta links
 \- uptime
    - uptime of mta (timescope --hours --minutes --seconds)
 \- msgprocessed
    - messages processed since start
 \- msgprocessed10
    - messages processed last 10 minutes

 - GWIA:
 \- uptime
    - uptime of gwia (timescope --hours --minutes --seconds)
 \- queues
    - e-mail queues of gwia (thresholds for outboundmsgqueue, inboundmsgqueue, smtpsendqueue, smtpreceivequeue, delayedmsqqueue must be defined comma seperated)
 \- stats
    - e-mail statistics of gwia since start
 \- statstime
    - e-mail statistics of gwia last x minutes (x defined in gwia)

 - POA:
 \- uptime
    - uptime of poa (timescope --hours --minutes --seconds)
 \- users
    - count of connected users

=item -h|--help

print help page

=item -V|--version

print plugin version

=cut

use strict;
use warnings;
use Getopt::Long qw(:config no_ignore_case bundling);
use Pod::Usage;
require LWP::UserAgent;
$ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 0;

# version string
my $version = 'Version: 1.1';

# command line parameters
my ( $help, $showVersion, $hostname, $user, $password, $mode, $command, $warning, $critical, $port, $ssl, $protocol, $hours, $minutes, $seconds);
our @state = ('OK', 'WARNING', 'CRITICAL', 'UNKNOWN');


GetOptions(
     "H|hostname:s"     => \$hostname,
     "S|ssl"     => \$ssl,
     "u|user:s"     => \$user,
     "p|password:s"     => \$password,
     "m|mode:s"     => \$mode,
     "l|command:s"     => \$command,
     "P|port:s"     => \$port,
     "w|warning:s"     => \$warning,
     "c|critical:s"     => \$critical,
     "h|help"     => \$help,
     "V|version"     => \$showVersion,
	  "hours"     => \$hours,
	  "minutes"     => \$minutes,
	  "seconds"     => \$seconds
);

# help and version page
if (defined $showVersion) { print $version."\n"; exit 0 }
if ($help) { pod2usage(1); }

if (!defined $hostname) { print "Option -H|--hostname is required\n"; pod2usage(2); }
if (!defined $mode) { print "Option -m|--mode is required\n"; pod2usage(2); }
if (!defined $command) { print "Option -l|--command is required\n"; pod2usage(2); }

# let's start...

# define vars
my $returnCode = 3;
my ($warnundeliverable, $warnerrors, $critundeliverable, $criterrors, $content, $url, $returnMessage, $warnoutbound, $warninbound, $warnsmtpsend, $warnsmtpreceive, $warndelayed, $critoutbound, $critinbound, $critsmtpsend, $critsmtpreceive, $critdelayed, $mtaname);
my $urlpath = "";

if ($mode eq "mta") {

     # set defaults
     if (!defined $port) { $port = "7180" };

     if ($command eq "uptime") {
          $urlpath = "home";
          Connect();
          ($mtaname) = ($content =~ /[\w\s\d]+MTA - ([\-\_\w\d]+)\s?</);
          $content =~ m/Up Time:\s(\d+)\sDays\s(\d+)\sHrs\s(\d+)\sMins/;
          my $time = int ($1*24*60*60)+($2*60*60)+($3*60);
			 my $unit = "seconds";
			 if (defined $hours) {
			      $time = ($time / 60 / 60);
					$unit = "hours";
          }
			 if (defined $minutes) {
			      $time = ($time / 60);
					$unit = "minutes";
          }
			 if (defined $seconds) {
			      $time = $time;
          }
          LeavePlugin (0, "$mtaname up since $time $unit|uptime=$time;;;;");
     } elsif ($command eq "links") {
          $urlpath = "home";
          Connect();
          my ($mtaopen, $mtaclosed, $poaopen, $poaclosed, $gatewayopen, $gatewayclosed) = ($content =~ m/Closed<\/FONT><\/TD>\n<\/TR><TR>\n<TD><FONT SIZE=-1>Domains<\/FONT><\/TD>\n<TD ALIGN="CENTER"><FONT SIZE=-1>(\d+)<\/FONT><\/TD>\n<TD ALIGN="CENTER"><FONT SIZE=-1>(\d+)<\/FONT><\/TD>\n<\/TR><TR>\n<TD><FONT SIZE=-1>Post Offices<\/FONT><\/TD>\n<TD ALIGN="CENTER"><FONT SIZE=-1>(\d+)<\/FONT><\/TD>\n<TD ALIGN="CENTER"><FONT SIZE=-1>(\d+)<\/FONT><\/TD>\n<\/TR><TR>\n<TD><FONT SIZE=-1>Gateways<\/FONT><\/TD>\n<TD ALIGN="CENTER"><FONT SIZE=-1>(\d+)<\/FONT><\/TD>\n<TD ALIGN="CENTER"><FONT SIZE=-1>(\d+)<\/FONT><\/TD>/i);

          if (($mtaclosed > 0) || ($poaclosed > 0) || ($gatewayclosed > 0)) {
               LeavePlugin (2, "Domains $mtaopen/$mtaclosed, Post Offices $poaopen/$poaclosed, Gateways $gatewayopen/$gatewayclosed (open/closed)");
          } else {
               LeavePlugin (0, "Domains $mtaopen/$mtaclosed, Post Offices $poaopen/$poaclosed, Gateways $gatewayopen/$gatewayclosed (open/closed)");
          }
     } elsif ($command eq "msgprocessed") {
          $urlpath = "home";
          Connect();
          (my $routed, my $routed10) = ($content =~ m/Routed[\<\>\/\w]+\n[\<\>\"\=\-\w\s]+>(\d+)[\<\/\w\>]+\n[\<\>\"\=\-\w\s]+>(\d+)/);
          (my $undeliverable, my $undeliverable10) = ($content =~ m/Undeliverable[\<\>\/\w]+\n[\<\>\"\=\-\w\s]+>(\d+)[\<\/\w\>]+\n[\<\>\"\=\-\w\s]+>(\d+)/);
          (my $errors, my $errors10) = ($content =~ m/Errors[\<\>\/\w]+\n[\<\>\"\=\-\w\s]+>(\d+)[\<\/\w\>]+\n[\<\>\"\=\-\w\s]+>(\d+)/);

          if (defined $warning) { ($warnundeliverable, $warnerrors) = ($warning =~ m/(\d+),(\d+)/); }
          if (defined $critical) { ($critundeliverable, $criterrors) = ($critical =~ m/(\d+),(\d+)/); }
          if (!defined $warnundeliverable) { $warnundeliverable = "5"; }
          if (!defined $warnerrors) { $warnerrors = "5"; }
          if (!defined $critundeliverable) { $critundeliverable = "10"; }
          if (!defined $criterrors) { $criterrors = "10"; }

          if (($undeliverable >= $critundeliverable) || ($errors >= $criterrors)) {
               LeavePlugin(2, "$routed Messages routed, $undeliverable Messages undeliverable, $errors Messages got errors.|routed=$routed;;;0; undeliverable=$undeliverable;$warnundeliverable;$critundeliverable;0; errors=$errors;$warnerrors;$criterrors;0;");
          } elsif ((($undeliverable >= $warnundeliverable) && ($undeliverable < $critundeliverable)) || (($errors >= $warnerrors ) && ($errors < $criterrors))) {
               LeavePlugin(1, "$routed Messages routed, $undeliverable Messages undeliverable, $errors Messages got errors.|routed=$routed;;;0; undeliverable=$undeliverable;$warnundeliverable;$critundeliverable;0; errors=$errors;$warnerrors;$criterrors;0;");
          } else {
               LeavePlugin(0, "$routed Messages routed, $undeliverable Messages undeliverable, $errors Messages got errors.|routed=$routed;;;0; undeliverable=$undeliverable;$warnundeliverable;$critundeliverable;0; errors=$errors;$warnerrors;$criterrors;0;");
          }
     } elsif ($command eq "msgprocessed10") {
          $urlpath = "home";
          Connect();
          (my $routed, my $routed10) = ($content =~ m/Routed[\<\>\/\w]+\n[\<\>\"\=\-\w\s]+>(\d+)[\<\/\w\>]+\n[\<\>\"\=\-\w\s]+>(\d+)/);
          (my $undeliverable, my $undeliverable10) = ($content =~ m/Undeliverable[\<\>\/\w]+\n[\<\>\"\=\-\w\s]+>(\d+)[\<\/\w\>]+\n[\<\>\"\=\-\w\s]+>(\d+)/);
          (my $errors, my $errors10) = ($content =~ m/Errors[\<\>\/\w]+\n[\<\>\"\=\-\w\s]+>(\d+)[\<\/\w\>]+\n[\<\>\"\=\-\w\s]+>(\d+)/);

          if (defined $warning) { ($warnundeliverable, $warnerrors) = ($warning =~ m/(\d+),(\d+)/); }
          if (defined $critical) { ($critundeliverable, $criterrors) = ($critical =~ m/(\d+),(\d+)/); }
          if (!defined $warnundeliverable) { $warnundeliverable = "5"; }
          if (!defined $warnerrors) { $warnerrors = "5"; }
          if (!defined $critundeliverable) { $critundeliverable = "10"; }
          if (!defined $criterrors) { $criterrors = "10"; }

          if (($undeliverable10 >= $critundeliverable) || ($errors10 >= $criterrors)) {
               LeavePlugin(2, "$routed10 Messages routed, $undeliverable10 Messages undeliverable, $errors10 Messages got errors in last 10 minutes.|routed10=$routed10;;;0; undeliverable10=$undeliverable10;$warnundeliverable;$critundeliverable;0; errors10=$errors10;$warnerrors;$criterrors;0;");
          } elsif ((($undeliverable10 >= $warnundeliverable) && ($undeliverable10 < $critundeliverable)) || (($errors10 >= $warnerrors ) && ($errors10 < $criterrors))) {
               LeavePlugin(1, "$routed10 Messages routed, $undeliverable10 Messages undeliverable, $errors10 Messages got errors in last 10 minutes.|routed10=$routed10;;;0; undeliverable10=$undeliverable10;$warnundeliverable;$critundeliverable;0; errors10=$errors10;$warnerrors;$criterrors;0;");
          } else {
               LeavePlugin(0, "$routed10 Messages routed, $undeliverable10 Messages undeliverable, $errors10 Messages got errors in last 10 minutes.|routed10=$routed10;;;0; undeliverable10=$undeliverable10;$warnundeliverable;$critundeliverable;0; errors10=$errors10;$warnerrors;$criterrors;0;");
          }
     } elsif ($command eq "info") {
          $urlpath = "server";
          Connect();
          ($mtaname) = ($content =~ /[\w\s\d]+MTA - ([\-\_\w\d]+)\s?</);
          (my $pid) = ($content =~ m/<TR><TD><FONT SIZE=-1>Main Thread Process ID<\/FONT><\/TD><TD><FONT SIZE=-1>(\d+)<\/FONT><\/TD><\/TR>/);
         # (my $version) = ($content =~ m/<FONT SIZE=-1>GroupWise Agent Build Version<\/FONT><\/TD><TD BGCOLOR="#FFFFFF">\n<FONT SIZE=-1>([\d\W]+)?\s+<\/FONT><\/TD><\/TR>/i);
          (my $version) = ($content =~ m/<FONT SIZE=-1>GroupWise Agent Build Version<\/FONT><\/TD><TD BGCOLOR="#FFFFFF">[\n]?<FONT SIZE=-1>([\d\w\.]+)[\s\W\d]+?<\/FONT><\/TD><\/TR>/i);
          LeavePlugin (0, "MTA/Domain: $mtaname; Version: $version; PID: $pid");
     } else {
          print "Unknown command for $mode in option -l|--command.\n"; pod2usage(1);
     }


} elsif ($mode =~ m/gwia/i) {

     # set defaults
     if (!defined $port) { $port = "9850" };

     Connect();

     my ($gwianame) = ($content =~ /<HEAD><TITLE>GroupWise GWIA - ([\d\w]+)./);

     if ($command eq "uptime") {
          $content =~ m/UpTime:\s+(\d+)\s+Days\s+(\d+)\s+Hrs\s+(\d+)\s+Mins/;
          my $time = ($1*24*60*60)+($2*60*60)+($3*60);
          LeavePlugin (0, "$gwianame up since $time seconds|uptime=$time;;;;");
     } elsif ($command eq "queues") {
          my ($outboundmsgqueue, $inboundmsgqueue, $smtpsendqueue, $smtpreceivequeue, $delayedmsqqueue) = ($content =~ m/<FONT SIZE=-1>Count<\/FONT><\/TD>\n[\<\w\s\d\=\#\"\>]+<FONT SIZE=-1>Oldest Message<\/FONT><\/TD>\n[\W\D\w\d\s\/\#\-\_\"\<\>\&]+<FONT SIZE=-1>Outbound Message Queues<\/FONT><\/TD>\n[\<\w\s\d\=\#\"\>]+<FONT SIZE=-1>(\d+)<\/FONT><\/TD>[\W\D\w\d\s\/\#\-\_\"\<\>\&]+Inbound Message Queues<\/FONT><\/TD>\n[\<\w\s\d\=\#\"\>]+<FONT SIZE=-1>(\d+)<\/FONT><\/TD>[\W\D\w\d\s\/\#\-\_\"\<\>\&]+SMTP Send Queue<\/FONT><\/TD>\n[\<\w\s\d\=\#\"\>]+<FONT SIZE=-1>(\d+)<\/FONT><\/TD>[\W\D\w\d\s\/\#\-\_\"\<\>\&]+SMTP Receive Queue<\/FONT><\/TD>\n[\<\w\s\d\=\#\"\>]+<FONT SIZE=-1>(\d+)<\/FONT><\/TD>[\W\D\w\d\s\/\#\-\_\"\<\>\&]+Delayed Message Queue<\/FONT><\/TD>\n[\<\w\s\d\=\#\"\>]+<FONT SIZE=-1>(\d+)<\/FONT><\/TD>/i);

          if (defined $warning) { ($warnoutbound, $warninbound, $warnsmtpsend, $warnsmtpreceive, $warndelayed) = ($warning =~ m/(\d+),(\d+),(\d+),(\d+),(\d+)/); }
          if (defined $critical) { ($critoutbound, $critinbound, $critsmtpsend, $critsmtpreceive, $critdelayed) = ($critical =~ m/(\d+),(\d+),(\d+),(\d+),(\d+)/); }
          if (!defined $warnoutbound) { $warnoutbound = "10"; }
          if (!defined $warninbound) { $warninbound = "10"; }
          if (!defined $warnsmtpsend) { $warnsmtpsend = "10"; }
          if (!defined $warnsmtpreceive) { $warnsmtpreceive = "10"; }
          if (!defined $warndelayed) { $warndelayed = "25"; }
          if (!defined $critoutbound) { $critoutbound = "25"; }
          if (!defined $critinbound) { $critinbound = "25"; }
          if (!defined $critsmtpsend) { $critsmtpsend = "25"; }
          if (!defined $critsmtpreceive) { $critsmtpreceive = "25"; }
          if (!defined $critdelayed) { $critdelayed = "50"; }

          if (($outboundmsgqueue >= $critoutbound) || ($inboundmsgqueue >= $critinbound) || ($smtpsendqueue >= $critsmtpsend) || ($smtpreceivequeue >= $critsmtpreceive) || ($delayedmsqqueue >= $critdelayed)) {
               LeavePlugin(2, "Outboundqueue: $outboundmsgqueue Inboundqueue: $inboundmsgqueue Sendqueue: $smtpsendqueue Receivequeue: $smtpreceivequeue Delayedqueue: $delayedmsqqueue|outboundmsgqueue=$outboundmsgqueue;$warnoutbound;$critoutbound;0; inboundmsgqueue=$inboundmsgqueue;$warninbound;$critinbound;0; smtpsendqueue=$smtpsendqueue;$warnsmtpsend;$critsmtpsend;0; smtpreceivequeue=$smtpreceivequeue;$warnsmtpreceive;$critsmtpreceive;0; delayedmsqqueue=$delayedmsqqueue;$warndelayed;$critdelayed;0;");
          } elsif ((($outboundmsgqueue >= $warnoutbound) && ($outboundmsgqueue < $critoutbound)) || (($inboundmsgqueue >= $warninbound) && ($inboundmsgqueue < $critinbound)) || (($smtpsendqueue >= $warnsmtpsend) && ($smtpsendqueue < $critsmtpsend)) || (($smtpreceivequeue >= $warnsmtpreceive) && ($smtpreceivequeue < $critsmtpreceive)) || (($delayedmsqqueue >= $warndelayed) && ($delayedmsqqueue < $critdelayed))) {
               LeavePlugin(1, "Outboundqueue: $outboundmsgqueue Inboundqueue: $inboundmsgqueue Sendqueue: $smtpsendqueue Receivequeue: $smtpreceivequeue Delayedqueue: $delayedmsqqueue|outboundmsgqueue=$outboundmsgqueue;$warnoutbound;$critoutbound;0; inboundmsgqueue=$inboundmsgqueue;$warninbound;$critinbound;0; smtpsendqueue=$smtpsendqueue;$warnsmtpsend;$critsmtpsend;0; smtpreceivequeue=$smtpreceivequeue;$warnsmtpreceive;$critsmtpreceive;0; delayedmsqqueue=$delayedmsqqueue;$warndelayed;$critdelayed;0;");
          } else {
               LeavePlugin(0, "Outboundqueue: $outboundmsgqueue Inboundqueue: $inboundmsgqueue Sendqueue: $smtpsendqueue Receivequeue: $smtpreceivequeue Delayedqueue: $delayedmsqqueue|outboundmsgqueue=$outboundmsgqueue;$warnoutbound;$critoutbound;0; inboundmsgqueue=$inboundmsgqueue;$warninbound;$critinbound;0; smtpsendqueue=$smtpsendqueue;$warnsmtpsend;$critsmtpsend;0; smtpreceivequeue=$smtpreceivequeue;$warnsmtpreceive;$critsmtpreceive;0; delayedmsqqueue=$delayedmsqqueue;$warndelayed;$critdelayed;0;");
          }
     } elsif ($command eq "stats") {
			 my ($normalout, $normalout10, $normalin, $normalin10, $bytesout, $bytesin) = ($content =~ m/[\d]+[\s]Minutes[\<\w\>\/]+\n?[\s\<\w\>\#\d\"\-\=]+Normal<\/FONT><\/TD>[\<\w\>\s\=\#\"\-]+<FONT SIZE=-1>(\d+)<\/FONT><\/TD>[\<\w\>\s\=\#\"\-]+<FONT SIZE=-1>(\d+)<\/FONT><\/TD>[\<\w\>\s\=\#\"\-]+<FONT SIZE=-1>(\d+)<\/FONT><\/TD>[\<\w\>\s\=\#\"\-]+<FONT SIZE=-1>(\d+)<\/FONT><\/TD><\/TR>[\<\w\>\s\=\#\"\-\d]+<FONT SIZE=-1>Status<\/FONT><\/TD>[\W\D\w\d\s\/\#\-\_\"\<\>]*Total Bytes<\/FONT><\/TD>[\<\w\>\s\=\#\"\-]+<FONT SIZE=-1>([\d\.]+)\s\w<\/FONT><\/TD>[\<\w\s\d\=\#\"\>]+&nbsp<\/TD>[\<\w\s\d\=\#\"\>]+<FONT SIZE=-1>([\d\.]+)\s\w<\/FONT><\/TD>[\<\w\s\d\=\#\"\>]+&nbsp<\/TD><\/TR>/i);
          LeavePlugin (0, "Since $gwianame start: $normalout E-Mails send, $normalin E-Mails received, $bytesout MB send, $bytesin MB received");
     } elsif ($command eq "stats10" || $command eq "statstime" ) {
			  my ($statsminutes, $normalout, $normalout10, $normalin, $normalin10, $bytesout, $bytesin) = ($content =~ m/([\d]+)[\s]Minutes[\<\w\>\/]+\n?[\s\<\w\>\#\d\"\-\=]+Normal<\/FONT><\/TD>[\<\w\>\s\=\#\"\-]+<FONT SIZE=-1>(\d+)<\/FONT><\/TD>[\<\w\>\s\=\#\"\-]+<FONT SIZE=-1>(\d+)<\/FONT><\/TD>[\<\w\>\s\=\#\"\-]+<FONT SIZE=-1>(\d+)<\/FONT><\/TD>[\<\w\>\s\=\#\"\-]+<FONT SIZE=-1>(\d+)<\/FONT><\/TD><\/TR>[\<\w\>\s\=\#\"\-\d]+<FONT SIZE=-1>Status<\/FONT><\/TD>[\W\D\w\d\s\/\#\-\_\"\<\>]*Total Bytes<\/FONT><\/TD>[\<\w\>\s\=\#\"\-]+<FONT SIZE=-1>([\d\.]+)\s\w<\/FONT><\/TD>[\<\w\s\d\=\#\"\>]+&nbsp<\/TD>[\<\w\s\d\=\#\"\>]+<FONT SIZE=-1>([\d\.]+)\s\w<\/FONT><\/TD>[\<\w\s\d\=\#\"\>]+&nbsp<\/TD><\/TR>/i);
          LeavePlugin (0, "Last $statsminutes Minutes: $normalout10 E-Mails send, $normalin10 E-Mails received|outgoing10=$normalout10;;;; incoming10=$normalin10;;;;");
     } else {
          print "Unknown command for $mode in option -l|--command.\n"; pod2usage(1);
     }

} elsif ($mode =~ m/poa/i) {

     # set defaults
     if (!defined $port) { $port = "7181" };

     Connect();

     my ($poaname) = ($content =~ /<HEAD><TITLE>GroupWise POA - ([\d\w\-]+)./);

     if ($command eq "uptime") {
          $content =~ m/Up\s+?Time:\s+(\d+)\sDays\s(\d+)\sHours\s(\d+)\sMinutes/;
          my $time = ($1*24*60*60)+($2*60*60)+($3*60);
          LeavePlugin (0, "$poaname up since $time seconds|uptime=$time;;;;");
     } elsif ($command eq "users") {
          my ($users) = ($content =~ m/>C\/S Users<\/FONT><\/A><\/TD>[\<\w\"\s\#\d\>\=]+[\n]?[\<\w\s\"\=\>]+<FONT SIZE=-1>(\d+)<\/FONT><\/TD>/i);

          if (($critical) && ($users >= $critical)) {
               LeavePlugin (2, "$users connected C/S Users|users=$users;;$critical;0;");
          } elsif (($warning) && ($critical) && ($warning <= $users) && ($critical > $users)) {
               LeavePlugin (1, "$users connected C/S Users|users=$users;$warning;$critical;0;");
          } elsif (($warning) && ($warning < $users)) {
               LeavePlugin (1, "$users connected C/S Users|users=$users;$warning;;0;");
          } elsif (($warning) && ($critical)) {
               LeavePlugin (0, "$users connected C/S Users|users=$users;$warning;$critical;0;");
          } elsif ($critical) {
               LeavePlugin (0, "$users connected C/S Users|users=$users;;$critical;0;");
          } elsif ($warning) {
               LeavePlugin (0, "$users connected C/S Users|users=$users;$warning;;0;");
          } else {
               LeavePlugin (0, "$users connected C/S Users|users=$users;;;0;");
          }
     } else {
          print "Unknown command for $mode in option -l|--command.\n"; pod2usage(1);
     }

} else {
     print "Unknown mode in option -m|--mode.\n"; pod2usage(1);
}


# functions

sub Connect {
     my $ua = LWP::UserAgent->new;
     $ua->timeout(30);
     $ua->env_proxy;
     $ua->ssl_opts( verify_hostnames => 0 );
     $ua->credentials("$hostname:$port","GroupWise Agent",$user=>$password);
     if ($ssl) { $protocol = "https"; } else  { $protocol = "http" };
     $url = "$protocol://$hostname:$port/$urlpath";
     $content = $ua->get( $url );
     $content = $content->decoded_content;
     if (!defined $content) { 
          LeavePlugin(2, "$mode ($url) is not reachable, please check connection settings!");
     } 
}

sub LeavePlugin {
     my $exitCode = $_[0];
     my $comment  = $_[1];
     
     print $state[$exitCode]." - $comment\n";
     exit $exitCode;
}

###
#     $content = $ua->get('$protocol://$hostname:$port/$urlpath');
#     $content = $ua->get('https://10.129.127.3:7180/home');

