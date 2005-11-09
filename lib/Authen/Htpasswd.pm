package Authen::Htpasswd;
$VERSION = '0.1';
use strict;
use base 'Class::Accessor::Fast';
use Carp;
use Fatal qw/ open close /;
use Authen::Htpasswd::User;

__PACKAGE__->mk_accessors(qw/ file encrypt_hash check_hashes /);

my $SUFFIX = '.new';

=head1 NAME

Authen::Htpasswd - interface to read and modify Apache .htpasswd files

=head1 SYNOPSIS
    
    my $pwfile = Authen::Htpasswd->new('user.txt', { encrypt_hash => 'md5' });
    
    # authenticate a user (checks all hash methods by default)
    if ($pwfile->check_user_password('bob', 'foo')) { ... }
    
    # modify the file (writes immediately)
    $pwfile->update_user('bob', $password, $info);
    $pwfile->add_user('jim', $password);
    $pwfile->delete_user('jim');
    
    # get user objects tied to a file
    my $user = $pwfile->lookup_user('bob');
    if ($user->check_password('vroom', [qw/ md5 sha1 /])) { ... } # only use secure hashes
    $user->password('foo'); # writes to file
    $user->set(password => 'bar', extra_info => 'editor'); # change more than one thing at once
    
    # or manage the file yourself
    my $user = Authen::Htpasswd::User->new('bill', { hashed_password => 'iQ.IuWbUIhlPE' });
    my $user = Authen::Htpasswd::User->new('bill', 'bar', 'staff', { encrypt_hash => 'crypt' });
    print PASSWD $user->to_line, "\n";

=head1 DESCRIPTION

This module provides a convenient, object-oriented interface to Apache-style C<.htpasswd> files.
It supports passwords encrypted via MD5, SHA1, and crypt, as well as plain (cleartext) passwords.
It requires L<Crypt::PasswdMD5> for MD5 and L<Digest::SHA1> for SHA1. The third field of the file
is also supported, referred to here as C<extra_info>.

=head1 METHODS

=over 4

=item new($filename, \%options)

Creates an object for a given C<.htpasswd> file.

=over 4

=item encrypt_hash

How passwords should be encrypted if a user is added or changed. Valid values are C<md5>, C<sha1>, 
C<crypt>, and C<plain>. Default is C<crypt>.

=item check_hashes

An array of hash methods to try when checking a password. The methods will be tried in the order
given. Default is C<md5>, C<sha1>, C<crypt>, C<plain>.

=back

=cut

sub new {
    my $class = shift;
    my $self = ref $_[-1] eq 'HASH' ? pop @_ : {};
    $self->{file} = $_[0] if $_[0];
    Carp::croak "no file specified" unless $self->{file};
    
    $self->{encrypt_hash} ||= 'crypt';        
    $self->{check_hashes} ||= [qw/ md5 sha1 crypt plain /];        

    bless $self, $class;
    $self;
}

=item lookup_user($username)

Returns an L<Authen::Htpasswd::User> object for the given user in the password file.

=cut

sub lookup_user {
    my ($self,$search_username) = @_;
    my $user;
    
    open my $fh, '<', $self->file;
    local $_;
    while (<$fh>) {
        chomp;
        my ($username,$hashed_password,$extra_info) = split /:/;
        if ($username eq $search_username) {
            $user = Authen::Htpasswd::User->new($username,undef,$extra_info, {
                    file => $self, 
                    hashed_password => $hashed_password,
                    encrypt_hash => $self->encrypt_hash, 
                    check_hashes => $self->check_hashes 
                });
            last;            
        }
    }
    close $fh;
    
    return $user;
}

=item check_user_password($username,$password)

Returns whether the password is valid. Shortcut for C<lookup_user->($username)->check_password($password)>.

=cut

sub check_user_password {
    my ($self,$username,$password) = @_;
    my $user = $self->lookup_user($username);
    Carp::croak "could not find user $username" unless $user;
    return $user->check_password($password);
}

=item update_user($userobj, \%options) or update_user($username, $password [, $extra_info], \%options)

Modifies the entry for a user saves it to the file. If the user entry does not
exist, it is created. Options are the same as for Authen::Htpasswd::User.

=cut

sub update_user {
    my $self = shift;
    my $user = $self->_get_user(@_);
    my $username = $user->username;

    my ($old,$new) = $self->_start_rewrite;
    local $_;
    my $seen = 0;
    while (<$old>) {
        if (/^\Q$username\:/) {
            chomp;
            my (undef,undef,$extra_info) = split /:/;
            $user->{extra_info} ||= $extra_info if defined $extra_info;
            print $new $user->to_line, "\n";
            $seen++;
        } else {
            print $new $_;
        }
    }
    print $new $user->to_line, "\n" unless $seen;
    $self->_finish_rewrite($old,$new);
}

=item add_user($userobj, \%options) or add_user($username, $password [, $extra_info], \%options)

Adds a user entry to the file. If the user entry already exists, an exception is raised.
Options are the same as for Authen::Htpasswd::User.

=cut

sub add_user {
    my $self = shift;
    my $user = $self->_get_user(@_);
    my $username = $user->username;

    my ($old,$new) = $self->_start_rewrite;
    local $_;
    while (<$old>) {
        if (/^\Q$username\:/) {
            $self->_abort_rewrite;
            Carp::croak "user $username already exists in " . $self->file . "!";
        }
        print $new $_;
    }
    print $new $user->to_line, "\n";
    $self->_finish_rewrite($old,$new);
}

=item delete_user($userobj) or delete_user($username)

Removes a user entry from the file.

=cut

sub delete_user {
    my $self = shift;
    my $username = $_[0]->isa('Authen::Htpasswd::User') ? $_[0]->username : $_[0];

    my ($old,$new) = $self->_start_rewrite;
    local $_;
    while (<$old>) {
        next if /^\Q$username\:/;
        print $new $_;
    }
    $self->_finish_rewrite($old,$new);
}

sub _get_user {
    my $self = shift;
    return $_[0] if $_[0]->isa('Authen::Htpasswd::User');
    my $attr = ref $_[-1] eq 'HASH' ? pop @_ : {};
    $attr->{encrypt_hash} ||= $self->encrypt_hash;
    $attr->{check_hashes} ||= $self->check_hashes;
    return Authen::Htpasswd::User->new(@_, $attr);
}

sub _start_rewrite {
    my $self = shift;
    open my $old, '<', $self->file;
    open my $new, '>', $self->file . $SUFFIX;
    return ($old,$new);
}

sub _finish_rewrite {
    my ($self,$old,$new) = @_;
    close $new; close $old;
    rename $self->file . $SUFFIX, $self->file;
}

sub _abort_rewrite {
    my ($self,$old,$new) = @_;
    close $new; close $old;
    unlink $self->file . $SUFFIX;    
}

=back

=head1 AUTHOR

David Kamholz

davekam at pobox dot com

=head1 SEE ALSO

L<Apache::Htpasswd>.

=cut

1;