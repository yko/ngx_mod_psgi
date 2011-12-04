use strict;
use warnings;
BEGIN {
    use Test::More;
    eval { require Plack::Test::Suite };
    if ($@) {
        plan skip_all => "Plack::Test::Suite required for this test";
    }
}
use FindBin;
use Cwd 'abs_path';

my $nginx     = 'http://nginx.org/download/nginx-1.0.4.tar.gz';
my $nginx_dir = 'nginx-1.0.4';
local $/ = undef;

my $home = abs_path("$FindBin::Bin/..");
my $tmp_conf = "$home/tmp/nginx.conf";
my $conf_template = "$home/eg/nginx.conf";
my $pidfile = "$home/tmp/nginx.pid";

Plack::Test::Suite->run_server_tests(\&run_httpd);
done_testing();

if (-f $pidfile) {
    my $pid = do { open my $PID, '<', $pidfile; <$PID> };
    kill 2, $pid;
}

sub run_httpd {
    my $port = shift;

    my $conf_body = do { open my $CNF, '<', $conf_template; <$CNF> };

    $conf_body
      =~ s#(\n\s*error_log\s+).*#$1"$home/log/error.local.log" debug;#;
    $conf_body =~ s#(\n\s*psgi)\s+.*#$1 "$home/eg/plack_test_suite.psgi";#;
    $conf_body =~ s#127\.0\.0\.1:\d+#127.0.0.1:$port#g;

    open my $CNF, '>', $tmp_conf
      or die "Unable to create temporarry conf '$tmp_conf': $!";
    print $CNF $conf_body;

    # Kill running nginx
    if (-f $pidfile) {

        my $pid = do { open my $PID, '<', $pidfile; <$PID> };
        kill 2, $pid;
    }

    system("$home/$nginx_dir/objs/nginx") and die "nginx failed to start\n";
    unlink $tmp_conf;
}
