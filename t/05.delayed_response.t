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
        psgi t/apps/05.delayed_response.psgi;
    }
--- request
    GET /
--- response_body_like: Delayed response body
--- response_headers
    test_header test_val
--- error_code: 202
