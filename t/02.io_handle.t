use Test::Nginx::Socket;

no_root_location();

plan tests => 3 * repeat_each() * blocks();

run_tests();

__DATA__
=== IO::Handle-like object represents body
--- config
    location / {
        psgi t/apps/02.io_handle.psgi;
    }
--- request: GET /
--- error_code: 200
--- response_headers
    test_header: test_val
--- response_body
Line by IO::Handle::OK
Line by IO::Handle::OK
Line by IO::Handle::OK
Line by IO::Handle::OK
Line by IO::Handle::OK
Line by IO::Handle::OK
Line by IO::Handle::OK
Line by IO::Handle::OK
Line by IO::Handle::OK
Line by IO::Handle::OK

=== IO::Handle-like object throws and error in getline()
--- config
    location / {
        psgi t/apps/02.io_handle.psgi;
    }
--- request: GET /getline_exception
--- error_code: 200
--- response_headers
    test-header: test_val
--- response_body
Line by IO::Handle::ErrorGetline
Line by IO::Handle::ErrorGetline
Line by IO::Handle::ErrorGetline
Line by IO::Handle::ErrorGetline
Line by IO::Handle::ErrorGetline
Line by IO::Handle::ErrorGetline

=== IO::Handle-like object throws and error in close()
--- config
    location / {
        psgi t/apps/02.io_handle.psgi;
    }
--- request: GET /close_exception
--- error_code: 200
--- response_headers
    test-header: test_val
--- response_body
Line by IO::Handle::ErrorClose
Line by IO::Handle::ErrorClose
Line by IO::Handle::ErrorClose
Line by IO::Handle::ErrorClose
Line by IO::Handle::ErrorClose
Line by IO::Handle::ErrorClose
Line by IO::Handle::ErrorClose
Line by IO::Handle::ErrorClose
Line by IO::Handle::ErrorClose
Line by IO::Handle::ErrorClose
