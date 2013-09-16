use strict;
use warnings;

use Test::Base -Base;
use Test::More;

use Test::Nginx::Util qw(
  run_tests
  $ServerPortForClient
  $RunTestHelper
  no_shuffle
  master_on
  master_off
  no_root_location
  get_nginx_version
  trim
);

eval { require Plack::Test::Suite }
  or plan skip_all => "Plack::Test::Suite required for this test";

$RunTestHelper = sub ($$) {
    my ($block, $dry_run) = @_;

    diag $block->name;

    my $mp = lc(trim($block->master_process || 'off'));

    if    ($mp eq 'off') { master_off() }
    elsif ($mp eq 'on')  { master_on() }
    else { BAIL_OUT("Unsupported value for master_process: '$mp'") }

    if (my $pid = fork) {
        waitpid $pid, 0;
        if ($?) {
            BAIL_OUT("Plack::Test::Suite exited with " . ($? >> 8));
        }
    }
    else {
        $Test::Nginx::Util::InSubprocess = 1;
        Plack::Test::Suite->run_server_tests(sub { }, $ServerPortForClient);
        exit;
    }
};

get_nginx_version();

diag "Testing nginx v$Test::Nginx::Util::NginxRawVersion";

no_root_location();

# Order matters here: once you set master_off, you can not switch back
no_shuffle();

run_tests();
done_testing();

__DATA__

=== Plack::Test::Suite with master process
--- config
    location / {
        psgi t/apps/00.plack_test_suite.psgi;
    }
--- master_process: on

=== Plack::Test::Suite without master process
--- config
    location / {
        psgi t/apps/00.plack_test_suite.psgi;
    }
--- master_process: off
