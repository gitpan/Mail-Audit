package Mail::Audit::KillDups;
use Mail::Audit;
use vars qw(@VERSION $dupfile);
$VERSION = '1.7';
$dupfile = ".msgid-cache";
1;

package Mail::Audit;
use strict;

sub killdups {
    my $item = shift;
    my $mid = $item->{obj}->head->get("Message-Id");
    if (open MSGID, $Mail::Audit::KillDups::dupfile) {
        while (<MSGID>) {
            chomp;
            if ($_ eq $mid) {
                _log(1, "Duplicate, ignoring");
                $item->ignore;
                return 1; # Just in case.
            }
        }
    }
    if (open MSGID, ">>".$Mail::Audit::KillDups::dupfile) {
        print MSGID $mid."\n";
        close MSGID;
    }
    return 0;
}


1;
__END__

=pod

=head1 NAME

Mail::Audit::KillDups - Mail::Audit plugin for duplicate suppression

=head1 SYNOPSIS

    use Mail::Audit qw(KillDups);
    $Mail::Audit::KillDups::dupfile = "/home/simon/.msgid-cache";
	my $mail = Mail::Audit->new;
    $mail->killdups;

=head1 DESCRIPTION

This is a Mail::Audit plugin which provides a method for checking
and supressing duplicate messages; that is, mails with message-ids which
have been previously seen.

=head2 METHODS

=over 4

=item C<killdups>

Checks the incoming message against a file of previously seen message
ids, ignores it if it's already seen, and adds it if it hasn't been.
C<$Mail::Audit::KillDups::dupfile> contains the name of the file used;
if you don't set this, it will be F<.msgid-cache> in the current
directory. (Probably your home directory.)

=head1 AUTHOR

Simon Cozens <simon@cpan.org>

=head1 SEE ALSO

L<Mail::Audit>
