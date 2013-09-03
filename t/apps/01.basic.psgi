#/usr/bin/env perl
use strict;
use warnings;

my $app = sub {
    return [201, [foo => "bar"], ["Hello ", "World", "!"]];
};

$app;
