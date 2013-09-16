use Test::Nginx::Socket;

unless ($ENV{WITH_DANCER}) {
    eval { require Dancer }
      or plan skip_all =>
      "You need Dancer framework installed to run this test";

    diag "using Dancer v$Dancer::VERSION";
}

no_root_location();

plan tests => 4 * repeat_each() * blocks();

run_tests();

__DATA__

=== TEST 2: Mojolicious::Lite: get title
--- config
    location / {
        psgi t/apps/frameworks/dancer.psgi;
    }
--- request: GET /hello/nginx
--- error_code: 200
--- response_body: Why, hello there nginx
--- response_headers
    Foo: Bar
    Hello: World!
