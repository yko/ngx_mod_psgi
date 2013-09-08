use Test::Nginx::Socket;

repeat_each(1);
no_root_location();

plan tests => 3 * repeat_each() * blocks();

run_tests();

__DATA__
=== IO::Handle-like object represents body
--- config
    location / {
        psgi t/apps/02.io_handle.psgi;
    }
--- request
    GET /
--- response_body_like: Line by IO::Handle::OK\nLine by IO::Handle::OK\nLine by IO::Handle::OK\nLine by IO::Handle::OK\nLine by IO::Handle::OK\nLine by IO::Handle::OK\nLine by IO::Handle::OK\nLine by IO::Handle::OK\nLine by IO::Handle::OK\nLine by IO::Handle::OK\n
--- response_headers
    test_header test_val
--- error_code: 200

=== IO::Handle-like object throws and error in getline()
--- config
    location / {
        psgi t/apps/02.io_handle.psgi;
    }
--- request
    GET /getline_exception
--- response_body_like: 500 Internal Server Error
--- response_headers
    test_header test_val
--- error_code: 200

=== IO::Handle-like object throws and error in close()
--- config
    location / {
        psgi t/apps/02.io_handle.psgi;
    }
--- request
    GET /close_exception
--- response_body_like: Line by IO::Handle::ErrorClose
--- response_headers
    test_header test_val
--- error_code: 200
