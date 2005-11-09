#!/perl

use Test::More tests => 24;

use strict;
use warnings;

use Authen::Htpasswd;

my $file = Authen::Htpasswd->new('t/data/passwd.txt');

ok( $file, 'object created successfully');

ok( $file->check_user_password(qw/ joe secret /, 'plaintext password verified') );
ok( !$file->check_user_password(qw/ joe tersec /, 'incorrect plaintext password rejected') );

ok( $file->check_user_password(qw/ bob margle /, 'crypt password verified') );
ok( !$file->check_user_password(qw/ bob foogle /, 'incorrect crypt password rejected') );

SKIP: {
    eval { use Crypt::PasswdMD5 };
    skip "Crypt::PasswdMD5 is required for md5 passwords", 1 if $@;
    ok( $file->check_user_password(qw/ bill blargle /, 'md5 password verified') );
    ok( !$file->check_user_password(qw/ bill fnord /, 'incorrect md5 password rejected') );
}

SKIP: {
    eval { use Digest; Digest->new("SHA-1") };
    skip "Digest::SHA1 is required for md5 passwords", 1 if $@;
    ok( $file->check_user_password(qw/ fred fribble /, 'sha1 password verified') );
    ok( !$file->check_user_password(qw/ fred frobble /, 'incorrect sha1 password rejected') );
}

$file->check_hashes([qw/ crypt /]);
ok( !$file->check_user_password(qw/ joe secret /), 'correct plaintext password denied');

use File::Copy;
copy('t/data/passwd.txt', 't/data/temp.txt') or die $!;

$file = Authen::Htpasswd->new('t/data/temp.txt');

ok( $file->add_user(qw/ jim frobnicate /), 'new user created' );
ok( $file->check_user_password(qw/ jim frobnicate /), 'new user verified' );

ok( $file->update_user(qw/ fred frobble /), 'user updated' );
ok( $file->check_user_password(qw/ fred frobble /), 'updated user verified' );
ok( !$file->check_user_password(qw/ fred fribble /), 'old password invalid' );

ok( $file->delete_user('jim'), 'deleted user' );
eval { $file->check_user_password(qw/ jim frobnicate /) };
ok( $@, 'deleted user not found' );

my $user = $file->lookup_user('bob');

ok( $user, 'looked up user' );
ok( $user->check_password('margle'), 'verified password' );
is( $user->extra_info, 'admin', 'verified extra info' );

ok( $user->password('farble'), 'changed password');
$user = $file->lookup_user('bob');
is( $user->extra_info, 'admin', 'extra info not clobbered');

ok( $user->extra_info('janitor'), 'changed extra info');
$user = $file->lookup_user('bob');
is( $user->extra_info, 'janitor', 'verified extra info');

unlink 't/data/temp.txt';