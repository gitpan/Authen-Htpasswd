use strict;
use Module::Build;

my $build = Module::Build->new(
    create_makefile_pl  => 'traditional',
    license             => 'perl',
    create_readme       => 1,

    module_name         => 'Authen::Htpasswd',
    requires            => {
        'perl'                      => '5.8.1',
        'Class::Accessor::Fast'     => 0
    },
    recommends => {
        'Crypt::PasswdMD5'  => 0, 
        'Digest::MD5'       => 0, 
        'Digest::SHA1'      => 0 
    }
);
$build->create_build_script;