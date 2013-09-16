use Test::Nginx::Socket;

no_root_location();

plan tests => 3 * repeat_each() * blocks();

run_tests();

__DATA__

=== delayed response
--- config
    location / {
        psgi t/apps/05.delayed_response.psgi;
    }
--- request: GET /
--- error_code: 202
--- response_headers
    test-header: test_val
--- response_body: Delayed response body
