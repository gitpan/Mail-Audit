package Mail::Audit;

use strict;
use Net::SMTP;
use Mail::Internet;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);
use Fcntl ':flock';
use constant REJECTED => 100;
use constant DELIVERED => 0;

$VERSION = '1.0';

sub new { bless({ obj => Mail::Internet->new(\*STDIN), @_ }, shift) }

sub accept {
	my $self = shift;
	my $file = shift || "/var/spool/mail/".getpwuid($>);
	return $self->{accept}->() if exists $self->{accept};
	open(FH, ">>$file") or die $!;
	flock(FH, LOCK_EX);
	print FH $self->{obj}->as_mbox_string;
	flock(FH, LOCK_UN);
	close FH;
	exit DELIVERED;
}

sub reject {
	my $self=shift;
	return $self->{reject}->() if exists $self->{reject};
	print STDERR @_;
	exit REJECTED;
}

sub pipe {
	my $self = shift;
	my $file = shift;
	return $self->{pipe}->() if exists $self->{pipe};
	open (PIPE, "|$file") or $self->accept();
	$self->{obj}->print(\*PIPE);
	close PIPE;
	exit DELIVERED;
}

sub tidy { $_[0]->{obj}->tidy() }
sub from { $_[0]->{obj}->head->get("From") }
sub to { $_[0]->{obj}->head->get("To") }
sub subject { $_[0]->{obj}->head->get("Subject") }
sub bcc { $_[0]->{obj}->head->get("Bcc") }
sub cc { $_[0]->{obj}->head->get("Cc") }
sub resend {$_[0]->{obj}->smtpsend(To => $_[1]) }
sub ignore { exit DELIVERED }

1;
__END__

=pod

=head1 NAME

Mail::Audit - Library for creating easy mail filters

=head1 SYNOPSIS

	use Mail::Audit;
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

=item C<new(%overrides)>

The constructor reads a mail message from C<STDIN> and creates a
C<Mail::Audit> object from it, to be manipulated by the following
methods.

You may optionally specify a hash with C<accept>, C<reject> or C<pipe>
keys and with subroutine references to override the methods with those
names. For example, people using MH as their mail handler will want to
override C<accept> to reflect the local delivery method of that mailer.

=back

=head2 METHODS

=over 4

=item C<accept($where)>

You can choose to accept the mail into a mailbox by calling the
C<accept> method; with no argument, this accepts to
F</var/spool/mail/you>. The mailbox is opened append-write, then locked
F<LOCK_EX>, the mail written and then the mailbox unlocked and closed.

If this isn't how you want local delivery to happen, you'll need to
override this method.

=item C<reject($reason)>

This rejects the email; it will be bounced back to the sender as
undeliverable. If a reason is given, this will be included in the
bounce.

=item C<ignore>

This merely ignores the email, dropping it into the bit bucket for
eternity.

=item C<pipe($program)>

This opens a pipe to an external program and feeds the mail to it.

=item C<tidy>

Tidies up the email as per L<Mail::Internet>

=item C<resent($address)>

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

Only tested on qmail and postfix, and I don't know how universally the
exit code 100 means reject.

=head1 AUTHOR

Simon Cozens <simon@cpan.org>

=head1 SEE ALSO

L<Mail::Internet>, L<Mail::SMTP>
