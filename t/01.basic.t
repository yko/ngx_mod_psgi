use Test::Nginx::Socket;

no_root_location();

plan tests => 3;

run_tests();

__DATA__

=== hello world app
--- config
    location / {
        psgi t/apps/01.basic.psgi;
    }
--- request: GET /
--- error_code: 201
--- response_headers
    foo: bar
--- response_body: Hello World!
