package Mail::Audit::MailInternet;

# $Id: MailInternet.pm,v 1.2 2002/01/15 17:06:23 mengwong Exp $

use strict;
use Mail::Internet;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);
@ISA = qw(Mail::Audit Mail::Internet);

$VERSION = '2.0';

sub autotype_new { 
    my $class = shift;
    my $self = shift;
    bless($self, $class);
}

sub is_mime        { 0; }

1;
