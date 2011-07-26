#/usr/bin/env perl
use strict;
use warnings;

use Data::Dumper;

my $app = sub {
    my $env = shift;

    my $errors = $env->{'psgi.errors'};
    my $input  = $env->{'psgi.input'};

    # Write some warnings to nginx log
    $errors->print("PSGI Hello World loaded");

    # Read whole body if any
    local $/ = undef;
    my $request_body = <$input>;

    return psgi_simple_response($env, $request_body);
    # return psgi_callback_using_responder($env, $request_body);
    # return psgi_callback_using_writer($env, $request_body);
};

# Applications MUST return a response as either a three element array reference,
# or a code reference for a delayed/streaming response.
# PSGI 1.09_3

sub psgi_simple_response {
    my ($env, $request_body) = @_;
    return [
        200,
        ['Content-Type' => 'text/plain', 'X-Header' => 'X-Header content'],
        [   "Hello World\n",
            "\n-- request body start\n",
            $request_body,
            "\n-- request body end\n",
            "\nPSGI ENV: ",
            Dumper($env)
        ]
    ];
}

# To enable a delayed response, the application SHOULD return a callback as its response.
# This callback will be called with another subroutine reference [responder] as its only argument.
# The responder should in turn be called with the standard three element array reference response.
# PSGI 1.09_3

sub psgi_callback_using_responder {
    my ($env, $request_body) = @_;
    return sub {
        my $responder = shift;
        $responder->(
            [   200,
                [   'Content-Type'        => 'text/plain',
                    'X-Responder-Obeject' => $responder
                ],
                ["Sample response line\n" x 100]
            ]
        );
    };
}

# An application MAY omit the third element (the body) when calling the responder.
# If the body is omitted,
# the responder MUST return yet another object
# which implements write and close methods.
# PSGI 1.09_3

sub psgi_callback_using_writer {
    my ($env, $request_body) = @_;
    return sub {
        my $responder = shift;
        my $writer = $responder->(
            [   200,
                [   'Content-Type'        => 'text/plain',
                    'X-Responder-Obeject' => $responder
                ]
            ]
        );

        for (1..1000) {
            $writer->write("I Want Cookies\n");
        }

        $writer->close;
    };
}

$app;
