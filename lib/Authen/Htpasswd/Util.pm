package Authen::Htpasswd::Util;
require Exporter;
@ISA = qw/ Exporter /;
@EXPORT = qw/ htpasswd_encrypt /;
use Digest;

my @CRYPT_CHARS = split(//, './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz');

=head1 NAME

Authen::Htpasswd::Util - performs encryption of supported .htpasswd formats

=head1 SYNOPSIS

    use Authen::Htpasswd::Util;
    my $hash = 'md5'; # can be md5, sha1, crypt, or plain
    my $hashed_pass = htpasswd_encrypt($hash,$password,$hashed_password); # exported by default

=cut

=head2 htpasswd_encrypt

=cut

sub htpasswd_encrypt {
    my ($hash,$password,$hashed_password) = @_;
    my $meth = __PACKAGE__->can("_hash_$hash");
    Carp::croak "don't know how to handle $hash hash" unless $meth;
    return &$meth($password,$hashed_password);
}

sub _supported_hashes {
    my @supported = qw/ crypt plain /;
    eval { Digest->new("SHA-1") };
    unshift @supported, 'sha1' unless $@;
    eval { require Crypt::PasswdMD5 };
    unshift @supported, 'md5' unless $@;
    return @supported;    
}

sub _hash_plain {
    my ($password) = @_;
    return $password;
}

sub _hash_crypt {
    my ($password,$salt) = @_;
    $salt = join('', @CRYPT_CHARS[int rand 64, int rand 64]) unless $salt;
    return crypt($password,$salt); 
}

sub _hash_md5 {
    my ($password,$salt) = @_;
    require Crypt::PasswdMD5;
    return Crypt::PasswdMD5::apache_md5_crypt($password,$salt);
}

sub _hash_sha1 {
    my ($password,$salt) = @_;
    my $sha1 = Digest->new("SHA-1");
    $sha1->add($password);
    return '{SHA}' . $sha1->b64digest . '=';
}

=head1 AUTHOR

David Kamholz C<dkamholz@cpan.org>

Yuval Kogman

=head1 COPYRIGHT & LICENSE

	Copyright (c) 2005 the aforementioned authors. All rights
	reserved. This program is free software; you can redistribute
	it and/or modify it under the same terms as Perl itself.

=cut

1;
