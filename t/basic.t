#!perl
use Test::More 'no_plan';
use File::Temp ();

BEGIN { use_ok('Mail::Audit'); }

sub readfile {
  my ($name) = @_;
  local *MESSAGE_FILE;
  open MESSAGE_FILE, "<$name" or die "coudn't read $name: $!";
  my @lines = <MESSAGE_FILE>;
  close MESSAGE_FILE;
  return \@lines;
}

my $message = readfile('t/messages/simple.msg');

my $maildir   = File::Temp::tempdir(CLEANUP => 1);
my $emergency = File::Temp::tempdir(CLEANUP => 1);

my $audit = Mail::Audit->new(
  data      => $message,
  emergency => $emergency,
);

isa_ok($audit, 'Mail::Audit');

# XXX: use catdir to make this OS-agnostic -- rjbs, 2006-06-01
ok((! -d "$emergency/new"), "emergency dir isn't a maildir before any accepts");
ok((! -d "$maildir/new"),   "and neither is the other temporary dir");

$audit->noexit(1);
$audit->accept($maildir);
$audit->noexit(0);

pass("we're still here! object-wide noexit was respected");

ok((! -d "$emergency/new"), "emergency dir isn't a maildir after first accept");
ok((  -d "$maildir/new"),   "but the other temporary dir is");

$audit->accept({ noexit => 1 });

ok((  -d "$emergency/new"), "after accept without dest, emergency is maildir");

pass("we're still still here! per-method noexit was respected");
