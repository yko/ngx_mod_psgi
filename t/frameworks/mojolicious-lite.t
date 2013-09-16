use Test::Nginx::Socket;

unless ($ENV{WITH_MOJOLICIOUS}) {
    eval { require Mojolicious }
      or plan skip_all =>
      "You need Mojolicious framework installed to run this test";

    diag "using Mojolicious v$Mojolicious::VERSION";
}

no_root_location();

plan tests => 4 * repeat_each() * blocks();

run_tests();

__DATA__

=== Mojolicious::Lite: sync request title
--- config
    location / {
        psgi t/apps/frameworks/mojolicious-lite.psgi;
    }
--- request: GET /hello/nginx
--- error_code: 200
--- response_headers
    Foo: Bar
    Hello: World!
--- response_body: Why, hello there nginx
