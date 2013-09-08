use Dancer;

set apphandler => 'PSGI';

get '/hello/:name' => sub {
    header('Foo' => 'Bar');
    header('Hello' => 'World!');
    return "Why, hello there " . params->{name};
};

dance;
