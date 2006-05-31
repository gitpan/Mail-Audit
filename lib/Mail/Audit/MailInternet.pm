package Mail::Audit::MailInternet;

# $Id: /my/icg/mail-audit/trunk/lib/Mail/Audit/MailInternet.pm 21840 2006-05-30T14:21:01.382064Z rjbs  $

use strict;
use Mail::Internet;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);
@ISA = qw(Mail::Audit Mail::Internet);

$VERSION = '2.0';

sub autotype_new {
  my $class = shift;
  my $self  = shift;
  bless($self, $class);
}

sub new {
  my $class = shift;
  my $type  = ref($class) || $class;

  # we want to create a subclass of Mail::Internet
  # call M::I's constructor
  my $self = Mail::Internet->new(@_);

  # now rebless it into this class
  bless $self, $type;
}

sub is_mime { 0; }

1;
