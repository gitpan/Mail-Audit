package Mail::Audit::PGP;
use Mail::Audit;
use vars qw(@VERSION);
$VERSION = '1.7';
1;

package Mail::Audit;
use strict;

sub fix_pgp_headers {
    my $item = shift;
    if ($item->body =~ /^-----BEGIN PGP MESSAGE-----/ and
        $item->body =~ /^-----END PGP MESSAGE-----/) {
        $item->put_header("Content-Type:", 
            "application/pgp; format=text; x-action=encrypt");
    }
    if ($item->body =~ /^-----BEGIN PGP SIGNED MESSAGE-----/ and
        $item->body =~ /^-----BEGIN PGP SIGNATURE-----/ and
        $item->body =~ /^-----END PGP SIGNATURE-----/) {
        $item->put_header("Content-Type:", 
            "application/pgp; format=text; x-action=sign");
    }
    return 0;
}


1;
__END__

=pod

=head1 NAME

Mail::Audit::PGP - Mail::Audit plugin for PGP header fixing

=head1 SYNOPSIS

    use Mail::Audit qw(PGP);
	my $mail = Mail::Audit->new;
    ...
    $mail->fix_pgp_headers;

=head1 DESCRIPTION

This is a Mail::Audit plugin which provides a method for checking
whether a given email contains a PGP-signed or -encrypted message, and
if so, adds the relevant headers to tell the mailer to check the
signature or decrypt it.

=head1 AUTHOR

Simon Cozens <simon@cpan.org>

=head1 SEE ALSO

L<Mail::Audit>
