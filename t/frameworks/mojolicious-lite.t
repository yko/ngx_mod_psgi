use Test::Nginx::Socket;

unless ($ENV{WITH_MOJOLICIOUS}) {
    eval { require Mojolicious }
      or plan skip_all =>
      "You need Mojolicious framework installed to run this test";

    diag "using Mojolicious v$Mojolicious::VERSION";
}

repeat_each(1);
no_root_location();

plan tests => 4 * repeat_each() * blocks();

run_tests();

__DATA__

=== Mojolicious::Lite: sync request title
--- config
    location / {
        psgi t/apps/frameworks/mojolicious-lite.psgi;
    }
--- request
    GET /hello/nginx
--- response_body_like: Why, hello there nginx
--- response_headers
    Foo: Bar
    Hello: World!
--- error_code: 200
