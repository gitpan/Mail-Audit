package Mail::Audit;

use strict;
use Net::SMTP;
use Mail::Internet;
use Sys::Hostname;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);
use Fcntl ':flock';
use constant REJECTED => 100;
use constant DELIVERED => 0;
my $loglevel=3;
my $logging =0;
my $logfile = "/tmp/".getpwuid($>)."-audit.log";

$VERSION = '1.7';

sub import {
    my $pkg = shift;
    for (@_) {
         eval "use $pkg"."::$_"; die $@ if $@;
    }
}

sub _log {
    my ($priority, $what) = @_; 
    if ($logging and $priority <= $loglevel) { print LOG "$what\n"; }
}

sub new { 
    my $class = shift;
    my %opts = @_;
    my $self = bless({ 
        %opts, 
        obj => Mail::Internet->new(
                    exists $opts{data}? $opts{data} : \*STDIN
                ) 
    }, $class) ;
    if (exists $self->{loglevel}) { 
        $logging =1;
        $loglevel = $self->{loglevel};
    }
    if (exists $self->{log}) {
        $logging = 1;
        $logfile = $self->{log};
    }
    if ($logging) {
        open LOG, ">>$logfile" or die $!;
        _log(1,"Logging started at ".scalar localtime);
        _log(2,"Incoming mail from ".$self->from);
        _log(2,"To: ".$self->to);
        _log(2,"Subject: ".$self->subject);
    }
    return $self;
}

sub accept {
	my $self = shift;
	my $file = shift || $ENV{MAIL} || "/var/spool/mail/".getpwuid($>);
    _log(1,"Accepting");
	return $self->{accept}->() if exists $self->{accept};
    _log(2,"Accepting to $file");
	# is it a Maildir?
	if (-d "$file/tmp" && -d "$file/new") {
		my $msg_file = "/${\time}.$$.${\hostname}";
		my $tmp_path = "$file/tmp/$msg_file";
		my $new_path = "$file/new/$msg_file";
        _log(3,"Looks like maildir, writing to $new_path");

		# since mutt won't add a lines tag to maildir messages,
		# we'll add it here
		unless ($self->{obj}->head->get("Lines")) {
			my $body = $self->{obj}->body;
			my $num_lines = @$body;
			$self->{obj}->head->add("Lines", $num_lines);
            _log(4,"Adding Lines: $num_lines header");
		}
		unless (open TMP, ">$tmp_path") {
            _log(0,"Couldn't open $tmp_path! $!");
            die $!;
        }
		print TMP $self->{obj}->as_mbox_string;
		close TMP;

		unless (link $tmp_path, $new_path) {
            _log(0,"Couldn't link $tmp_path to $new_path : $!");
            die $!;
        }
		unlink $tmp_path or _log(1,"Couldn't unlink $tmp_path: $!");
	} else { # it's an mbox
		unless (open(FH, ">>$file")) {
            _log(0,"Couldn't open $file! $!");
            die $!;
        }
		flock(FH, LOCK_EX) 
            or _log(1,"Couldn't get exclusive lock on $file");
        seek FH, 0, 2;
		if ((${$self->{obj}->body}[0] !~ /^From\s/) && (exists $ENV{UFLINE})) {
		    _log(3,"Looks qmail, but preline not run, prepending UFLINE, RPLINE, DTLINE");
			print FH $ENV{UFLINE};
			print FH $ENV{RPLINE};
			print FH $ENV{DTLINE};
		}
		print FH $self->{obj}->as_mbox_string;
		flock(FH, LOCK_UN)
            or _log(1,"Couldn't unlock on $file");
		close FH;
	}
    if (!$self->{noexit}) {
        _log(2,"Exiting with status ".DELIVERED);
	exit DELIVERED;
    }
}

sub reject {
	my $self=shift;
	return $self->{reject}->() if exists $self->{reject};
        _log(1, "Rejecting with reason @_");
	print STDERR @_;
    if (!$self->{noexit}) {
        _log(2,"Exiting with status ".REJECTED);
	exit REJECTED;
    }
}

sub pipe {
	my $self = shift;
	my $file = shift;
	return $self->{pipe}->() if exists $self->{pipe};
        _log(1, "Piping to $file");
	unless (open (PIPE, "|$file")) {
            _log(0, "Couldn't open pipe $file: $!");
            $self->accept();
        }
	$self->{obj}->print(\*PIPE);
	close PIPE;
        _log(3,"Pipe closed with status $?");
        if (!$self->{noexit}) {
            _log(2,"Exiting with status ".DELIVERED);
            exit DELIVERED;
        }
}

sub header { $_[0]->{obj}->head->as_string() }
sub tidy { $_[0]->{obj}->tidy_body() }
sub from { $_[0]->{obj}->head->get("From") }
sub to { $_[0]->{obj}->head->get("To") }
sub subject { $_[0]->{obj}->head->get("Subject") }
sub bcc { $_[0]->{obj}->head->get("Bcc") }
sub cc { $_[0]->{obj}->head->get("Cc") }
sub body { $_[0]->{obj}->body }
sub received { $_[0]->{obj}->head->get("Received") }
sub get { $_[0]->{obj}->head->get($_[1]) }
sub resend {$_[0]->{obj}->smtpsend(To => $_[1]) }
sub ignore { _log(1,"Ignoring"); exit DELIVERED unless $_[0]->{noexit} }

sub myALRM { die "alarm\n" }
sub rblcheck {
my ($self, $timeout) = (shift, shift);
_log(1,"Performing RBL check");
my @recieved      = $self->received;
my $rcvcount      = 0;
$timeout = 10 unless defined $timeout;

# Catch ALRM signals so we can timeout DNS lookups
$SIG{ALRM} = 'myALRM';
&myALRM() if 0;              # make -w shut up
for (@recieved) {
    my $x = _checkit($rcvcount,$_,$timeout);
    if ($x) {
        _log(2, "Check returned $x after ".(1+$rcvcount)." recieved headers");
        return $x
    }
    $rcvcount++;  # Any further Received lines won't be the first.
}
_log(2, "Check was fine");
return '';
}

sub checkit {
    my $MAPS          = '.rbl.maps.vix.com';
    my $OK            = '';
    my $InvalidIP     = '1 Invalid IP address ';
    my $RcvBlackHole  = '2 Received from RBL-registered spam site ';
    my $RlyBlackHole  = '3 Relayed through RBL-registered spam site ';

   my($relay,$rcvd,$timeout) = @_;
   my($IP,@IP) = $rcvd =~ /\[((\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3}))\]/;
   my($name,$x);
   # We can't complain if there's no IP address in this Received header.
   return ($OK) unless defined $IP;
   # Outer limits lose
   return ($InvalidIP.$IP) if $IP eq '0.0.0.0';
   return ($InvalidIP.$IP) if $IP eq '255.255.255.255';
   # All @IP components must be >= 0 and <= 255
   foreach $x ( @IP ) {
      return ($InvalidIP.$IP) if $x > 255;
      return ($InvalidIP.$IP) if $x =~ /^0\d/;    # no leading zeroes allowed
   }
   #
   # Wrap the gethostbyname call with eval in case it times out.
   #
   eval {
      alarm($timeout);
      ($name) = gethostbyname(join('.',reverse @IP) . $MAPS);
      alarm(0);
   };
   return($OK) if $@ =~ /^alarm/;  # Timed out.  Let it through.
   return($OK) unless $name;       # If it's ok with MAPS, it's OK with us.
   return($relay ? $RlyBlackHole.$IP : $RcvBlackHole.$IP);
}


1;
__END__

=pod

=head1 NAME

Mail::Audit - Library for creating easy mail filters

=head1 SYNOPSIS

	use Mail::Audit; # use Mail::Audit qw(...plugins...);
	my $mail = Mail::Audit->new;
	$mail->pipe("listgate p5p") if ($mail->from =~ /perl5-porters/);
	$mail->accept("perl) if ($mail->from =~ /perl/);
	$mail->reject("We do not accept spam") if looks_like_spam($mail);
	$mail->ignore if $mail->subject =~ /boring/i;
	...

=head1 DESCRIPTION

F<procmail> is nasty. It has a tortuous and complicated recipe format,
and I don't like it. I wanted something flexible whereby I could filter
my mail using Perl tests.

C<Mail::Audit> was inspired by Tom Christiansen's F<audit_mail> and
F<deliverlib> programs. It allows a piece of email to be logged,
examined, accepted into a mailbox, filtered, resent elsewhere, rejected,
and so on. It's designed to allow you to easily create filter programs
to stick in a F<.forward> file or similar.

=head2 CONSTRUCTOR

=over 4

=item C<new(%options)>

The constructor reads a mail message from C<STDIN> (or, if the C<data>
option is set, from an array reference) and creates a C<Mail::Audit>
object from it, to be manipulated by the following methods.

Other options include the C<accept>, C<reject> or C<pipe> keys, which
specify subroutine references to override the methods with those names.

You may also specify C<< log => $logfile >> to write a debugging log; you
can set the verbosity of the log with the C<loglevel> key, on a scale of
1 to 4. If you specify a log level without a log file, logging will be
written to F</tmp/you-audit.log> where F<you> is replaced by your user
name. If you specify C<< noexit => 1 >>, C<Mail::Audit> will not exit
after delivering the mail, but continue running your filter. 

=back

=head2 METHODS

=over 4

=item C<accept($where)>

You can choose to accept the mail into a mailbox by calling the
C<accept> method; with no argument, this accepts to
F</var/spool/mail/you>. The mailbox is opened append-write, then locked
F<LOCK_EX>, the mail written and then the mailbox unlocked and closed.
If Mail::Audit sees that you have a maildir style system, where
F</var/spool/mail/you> is a directory, it'll deliver in maildir style.

If this isn't how you want local delivery to happen, you'll need to
override this method.

=item C<reject($reason)>

This rejects the email; it will be bounced back to the sender as
undeliverable. If a reason is given, this will be included in the
bounce.

=item C<ignore>

This merely ignores the email, dropping it into the bit bucket for
eternity.

=item C<rblcheck([$timeout])>

Attempts to check the mail headers with the Relay Blackhole List. 
Returns false if the headers check out fine or the query times out,
returns a reason if the mail is considered spam.

=item C<pipe($program)>

This opens a pipe to an external program and feeds the mail to it.

=item C<tidy>

Tidies up the email as per L<Mail::Internet>

=item C<get($header)>

Retrieves the named header from the mail message.

=item C<body>

Returns an array of lines in the body of the email.

=item C<header>

Returns the header as a single string.

=item C<resend($address)>

Bounces the email in its entirety to another address.

=back

=head2 ATTRIBUTES

The following attributes correspond to fields in the mail:

=over 4

=item *

from

=item *

to

=item *

subject

=item *

cc

=item *

bcc

=back

=head1 BUGS

Fewer than before.

=head1 AUTHOR

Simon Cozens <simon@cpan.org>

=head1 SEE ALSO

L<Mail::Internet>, L<Mail::SMTP>
