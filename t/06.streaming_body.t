use Test::Nginx::Socket;

no_root_location();

plan tests => 3 * repeat_each() * blocks();

run_tests();

__DATA__

=== streaming body
--- config
    location / {
        psgi t/apps/06.streaming_body.psgi;
    }
--- request: GET /
--- error_code: 201
--- response_headers
    Content-Encoding text/json
--- response_body_like: Hello Streaming World!

