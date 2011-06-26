#/usr/bin/env perl
use strict;
use warnings;

use Data::Dumper;

sub {
    my $env = shift;

    my $errors = $env->{'psgi.errors'};
    my $input  = $env->{'psgi.input'};

    # Write some warnings to nginx log
    $errors->print("PSGI Hello World loaded!");

    # Read whole body if any
    local $/ = undef;
    my $buffer = <$input>;

    # Return PSGI response
    return [
        404,
        ['Content-Type' => 'text/plain', 'X-header' => 'X-Header content'],
        [   "Hello World",
            "\nRequest body:\n",
            $buffer,
            "\n\nPSGI ENV:\n",
            Dumper($env)
        ]
    ];
};
