#/usr/bin/env perl
use strict;
use warnings;
{
    package IO::Handle::OK;

    sub new {
        my $class = shift;
        return bless {lines => 10, @_}, $class;
    }
    sub close { return 1 }

    sub getline {
        my $self = shift;
        return $self->{lines}-- ? "Line by " . ref($self) . "\n" : undef;
    }
};
{
    package IO::Handle::ErrorClose;
    use base 'IO::Handle::OK';
    sub close { die ref(shift) . " died in close()" }
};
{
    package IO::Handle::ErrorGetline;
    use base 'IO::Handle::OK';

    sub getline {
        if ($_[0]->{lines} < 5) {
            die ref(shift) . " died in getline()";
        }
        shift->SUPER::getline(@_);
    }
};

my $app = sub {
    my $env = shift;

    my $headers = [test_header => "test_val"];

    my $body;
    if ($env->{REQUEST_URI} eq '/getline_exception') {
        $body = 'IO::Handle::ErrorGetline';
    }
    elsif ($env->{REQUEST_URI} eq '/close_exception') {
        $body = 'IO::Handle::ErrorClose';
    }
    else {
        $body = 'IO::Handle::OK';
    }

    return [200, $headers, $body->new];
};

$app;
