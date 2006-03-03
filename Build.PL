use strict;
use Module::Build;

my $build = Module::Build->new(
    create_makefile_pl  => 'traditional',
    license             => 'perl',
    create_readme       => 1,

    module_name         => 'Authen::Htpasswd',
    requires            => {
        'Class::Accessor::Fast'     => 0,
        'IO::LockedFile'            => 0,
        'Digest'                    => 0,
    },
    recommends => {
        'Crypt::PasswdMD5'  => 0, 
        'Digest::SHA1'      => 0,
    },

    dist_author => 'David Kamholz <dkamholz@cpan.org>',
);
$build->create_build_script;
