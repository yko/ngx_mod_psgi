#/usr/bin/env perl
use strict;
use warnings;

my $app = sub {
    my $env = shift;

    # immediately starts the response and stream the content
    return sub {
        my $responder = shift;
        my $writer =
          $responder->([203, ['Content-Type', 'application/json']]);

        wait_for_events(
            sub {
                my $new_event = shift;
                $writer->write("{\n");
                if ($new_event) {
                    $writer->write(" '$new_event': 1,\n");
                }
                else {
                    $writer->write(" EOL: 1\n}");
                    $writer->close;
                }
            }
        );
    };
};

sub wait_for_events {
    my $callback = shift;
    my @words = split /\b/, 'Hello World!';
    $callback->($_) for @words;
    $callback->();
}

$app;
