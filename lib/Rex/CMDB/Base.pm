#
# (c) Jan Gehring <jan.gehring@gmail.com>
#
# vim: set ts=2 sw=2 tw=0:
# vim: set expandtab:

package Rex::CMDB::Base;

use 5.010001;
use strict;
use warnings;

our $VERSION = '9999.99.99_99'; # VERSION

use Rex::Helper::Path;
use Rex::Hardware;
use Rex::Hardware::Host;

sub new {
  my $that  = shift;
  my $proto = ref($that) || $that;
  my $self  = {@_};

  bless( $self, $proto );

  return $self;
}

sub _parse_path {
  my ( $self, $path, $mapping ) = @_;

  return parse_path( $path, $mapping );
}

sub _get_cmdb_files {
  my ( $self, $item, $server ) = @_;

  $server = $self->_get_hostname_for($server);

  my @files;

  if ( !ref $self->{path} ) {
    my $env          = Rex::Commands::environment();
    my $server_file  = "$server.yml";
    my $default_file = 'default.yml';
    @files = (
      File::Spec->join( $self->{path}, $env, $server_file ),
      File::Spec->join( $self->{path}, $env, $default_file ),
      File::Spec->join( $self->{path}, $server_file ),
      File::Spec->join( $self->{path}, $default_file ),
    );
  }
  elsif ( ref $self->{path} eq "CODE" ) {
    @files = $self->{path}->( $self, $item, $server );
  }
  elsif ( ref $self->{path} eq "ARRAY" ) {
    @files = @{ $self->{path} };
  }

  my $os = Rex::Hardware::Host->get_operating_system();

  @files = map {
    $self->_parse_path( $_, { hostname => $server, operatingsystem => $os, } )
  } @files;

  return @files;
}

sub _get_hostname_for {
  my ( $self, $server ) = @_;

  my $hostname = $server // Rex::get_current_connection()->{conn}->server->to_s;

  if ( $hostname eq '<local>' ) {
    my %hw_info = Rex::Hardware->get('Host');
    $hostname = $hw_info{Host}{hostname};
  }

  return $hostname;
}

1;
