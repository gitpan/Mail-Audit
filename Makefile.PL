use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
  'NAME'	=> 'Mail::Audit',
  'VERSION_FROM' => 'lib/Mail/Audit.pm', # finds $VERSION
  'PREREQ_PM' => {
    'MIME::Entity' => 0,
    'Mail::Internet' => 0,
    'Mail::Mailer' => 0,
    'Net::SMTP' => 0,
    'Fcntl' => 0
  }
);
