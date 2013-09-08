use Mojolicious::Lite;

# Blocking
get '/hello/:name' => sub {
    my $self = shift;

    $self->res->headers->add(Foo => 'Bar');
    $self->res->headers->add(Hello => 'World!');

    $self->render(data => "Why, hello there " . $self->stash('name'));
};

app->start('psgi');
