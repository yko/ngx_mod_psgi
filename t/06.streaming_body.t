use Test::Nginx::Socket;

repeat_each(1);
no_root_location();

plan tests => 3 * repeat_each() * blocks();

run_tests();

__DATA__

=== TEST 1: sanity
--- config
    location / {
        # Install psgi app
        # to server requests at certain address
        psgi t/apps/06.streaming_body.psgi;
    }
--- request
    GET /
--- response_body_like: Streaming response body
--- response_headers
    Content-Encoding text/json
--- error_code: 203

