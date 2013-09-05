#/usr/bin/env perl
use strict;
use warnings;

my $app = sub {
    my $env = shift;

    # immediately starts the response and stream the content
    return sub {
        my $responder = shift;
        my $writer =
          $responder->([201, ['Content-Type', 'application/json']]);

        my @words = split /\b/, 'Hello Streaming World!';
        $writer->write($_) for @words;
        $writer->close();
    };
};

$app;
