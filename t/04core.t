#!/perl

use Test::More tests => 10;

use strict;
use warnings;
use Authen::Htpasswd;

my $file = Authen::Htpasswd->new('t/data/passwd.txt');

ok( $file, 'object created successfully');

ok( $file->check_user_password(qw/ joe secret /), 'plaintext password verified' );
ok( !$file->check_user_password(qw/ joe tersec /), 'incorrect plaintext password rejected' );

ok( $file->check_user_password(qw/ bob margle /), 'crypt password verified' );
ok( !$file->check_user_password(qw/ bob foogle /), 'incorrect crypt password rejected' );

SKIP: {
    skip "Crypt::PasswdMD5 is required for md5 passwords", 2 unless grep { $_ eq 'md5' } @{$file->check_hashes};
    ok( $file->check_user_password(qw/ bill blargle /), 'md5 password verified' );
    ok( !$file->check_user_password(qw/ bill fnord /), 'incorrect md5 password rejected' );
}

SKIP: {
    skip "Digest::SHA1 is required for md5 passwords", 2 unless grep { $_ eq 'sha1' } @{$file->check_hashes};
    ok( $file->check_user_password(qw/ fred fribble /), 'sha1 password verified' );
    ok( !$file->check_user_password(qw/ fred frobble /), 'incorrect sha1 password rejected' );
}

$file->check_hashes([qw/ crypt /]);
ok( !$file->check_user_password(qw/ joe secret /), 'correct plaintext password denied');

