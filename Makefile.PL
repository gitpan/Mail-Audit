use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'	=> 'Mail::Audit',
    'VERSION_FROM' => 'Audit.pm', # finds $VERSION
	'PREREQ_PM' => {
		'Mail::Internet' => 0,
		'Net::SMTP' => 0,
		'Fcntl' => 0
	}
);
