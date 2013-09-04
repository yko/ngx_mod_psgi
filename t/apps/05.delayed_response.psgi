#/usr/bin/env perl
use strict;
use warnings;

my $app = sub {
    my $env = shift;

    my $headers = [test_header => "test_val"];

    # Delays response until it fetches content from the network
    return sub {
        my $responder = shift;

        fetch_content_from_server(
            sub {
                my $content = shift;
                $responder->([202, $headers, [$content]]);
            }
        );
    };
};

sub fetch_content_from_server {
    my $callback = shift;
    $callback->("Delayed response body");
}

$app;
