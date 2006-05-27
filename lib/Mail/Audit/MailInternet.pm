package Mail::Audit::MailInternet;

# $Id: MailInternet.pm,v 1.2 2002/05/04 05:07:27 waltman Exp $

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

sub new {
    my $class = shift;
    my $type = ref($class) || $class;

    # we want to create a subclass of Mail::Internet
    # call M::I's constructor
    my $self = Mail::Internet->new(@_);

    # now rebless it into this class
    bless $self, $type;
}

sub is_mime        { 0; }

1;
