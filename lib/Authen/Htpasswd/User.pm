package Authen::Htpasswd::User;
use strict;
use base 'Class::Accessor::Fast';
use Carp;
use Authen::Htpasswd;
use Authen::Htpasswd::Util;

use overload '""' => \&to_line;

__PACKAGE__->mk_accessors(qw/ file encrypt_hash check_hashes /);

=head1 NAME

Authen::Htpasswd::User - represents a user line in a .htpasswd file

=head1 SYNOPSIS

    my $user = Authen::Htpasswd::User->new($username, $password[, $extra_info], \%options);
    my $user = $pwfile->lookup_user($username); # from Authen::Htpasswd object
    
    if ($user->check_password($password)) { ... }
    if ($user->hashed_password eq $foo) { ... }
    
    # these are written immediately if the user was looked up from an Authen::Htpasswd object
    $user->username('bill');
    $user->password('bar');
    $user->hashed_password('tIYAwma5mxexA');
    $user->extra_info('root');
    $user->set(username => 'bill', password => 'foo'); # set several at once
    
    print $user->to_line, "\n";
 
=head1 METHODS

=head2 new

    my $userobj = Authen::Htpasswd::User->new($username, $password[, $extra_info], \%options);

Creates a user object. You may also specify the arguments and options together in a hash: 
C<< { username => $foo, password => $bar, extra_info => $baz, ... } >>.

=over 4

=item encrypt_hash

=item check_hashes

See L<Authen::Htpasswd>.

=item hashed_password

Explicitly sets the value of the hashed password, rather than generating it with C<password>.

=back

=cut

sub new {
    my $class = shift;
    Carp::croak "not enough arguments" if @_ < 2;
    
    my $self = ref $_[-1] eq 'HASH' ? pop @_ : {};
    $self->{encrypt_hash} ||= 'crypt';
    $self->{check_hashes} ||= [qw/ md5 sha1 crypt plain /];

    $self->{username} = $_[0];
    $self->{hashed_password} ||= htpasswd_encrypt($self->{encrypt_hash}, $_[1]) if defined $_[1];
    $self->{extra_info} = $_[2] if defined $_[2];

    bless $self, $class;
}

=head2 check_password

    $userobj->check_password($password,\@check_hashes);

Returns whether the password matches. C<check_hashes> is the same as for Authen::Htpasswd.

=cut

sub check_password {
    my ($self,$password,$hashes) = @_;
    $hashes ||= $self->check_hashes;
    foreach my $hash (@$hashes) {
        return 1 if $self->hashed_password eq htpasswd_encrypt($hash, $password, $self->hashed_password);
    }
    return 0;
}

=head2 username

=head2 hashed_password

=head2 extra_info

These methods get and set the three fields of the user line. If the user was looked up from an Authen::Htpasswd
object, the changes are written immediately to the assciated file. The same goes for C<password> and C<set> below.

=cut

sub username {
    my $self = shift;
    if (@_) {
        $self->{username} = shift;
        $self->file->update_user($self) if $self->file;        
    }
    return $self->{username};
}

sub hashed_password {
    my $self = shift;
    if (@_) {
        $self->{hashed_password} = shift;
        $self->file->update_user($self) if $self->file;        
    }
    return $self->{hashed_password};
}

sub extra_info {
    my $self = shift;
    if (@_) {
        $self->{extra_info} = shift;
        $self->file->update_user($self) if $self->file;        
    }
    return $self->{extra_info};
}

=head2 password
    
    $userobj->password($newpass);

Encrypts a new password.

=cut

sub password {
    my ($self,$password) = @_;
    $self->hashed_password( htpasswd_encrypt($self->encrypt_hash, $password) );
}

=head2 set

    $userobj->set(item => $value, ...);

Sets any of the four preceding values at once. Only writes the file once if it is going to be written.

=cut

sub set {
    my ($self,%attr) = @_;
    while (my ($key,$value) = each %attr) {
        if ($key eq 'password') {
            $self->{hashed_password} = htpasswd_encrypt($self->encrypt_hash, $value);
        } else {
            $self->{$key} = $value;            
        }
    }
    $self->file->update_user($self) if $self->file;        
}

=head2 to_line

    $userobj->to_line;

Returns a line for the user, suitable for printing to a C<.htpasswd> file. There is no newline at the end.

=cut

sub to_line {
    my $self = shift;
    return join(':', $self->username, $self->hashed_password,
        defined $self->extra_info ? $self->extra_info : ());
}

=head1 AUTHOR

David Kamholz

davekam at pobox dot com

=cut

1;