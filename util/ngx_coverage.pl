#!/usr/bin/env perl
use strict;
use warnings;
use Carp ();
use Cwd 'realpath', 'getcwd';
use File::Basename;
use File::Find;
use File::Path 'remove_tree';
use File::Spec::Functions ':ALL';
use File::Temp;
use Getopt::Long;
use Pod::Usage;

my %opts = (
    nginx_dir      => undef,
    verbose        => 0,
    module_dir     => '.',
    module_sources => 'src',
    prove_command  => undef,
    test_sources   => []
);

GetOptions(
    'm|module-dir=s'   => \$opts{module_dir},
    'module-sources=s' => \$opts{module_sources},
    'v|verbose'        => \$opts{verbose},
    'test-source=s'    => $opts{test_sources},
    'prove-command=s'  => \$opts{prove_command},
    'h|help'           => sub { pod2usage(1) },
);

pod2usage(-message => basename($0) . ": Nginx dir required.\n")
  unless @ARGV;

pod2usage(-message => basename($0) . ": Too many argumets given.\n")
  if @ARGV > 1;

$opts{nginx_dir} = $ARGV[0];

$opts{nginx_objdir}   = catdir($opts{nginx_dir},    'objs');
$opts{nginx_makefile} = catdir($opts{nginx_objdir}, 'Makefile');
$opts{nginx_bin}      = catdir($opts{nginx_objdir}, 'nginx');

$opts{module_dir} = realpath($opts{module_dir});

if (!@{$opts{test_sources}}) {
    $opts{test_sources} = ['t'];
    verbose("No test-sources defined. Using default @{$opts{test_sources}}");
}

check_opts(\%opts);
my @sources = find_sources(catdir($opts{module_dir}, $opts{module_sources}));
make_nginx(\%opts, \@sources);
make_coverage(\%opts, \@sources);

sub make_coverage {
    my ($opts, $sources) = @_;

    local $ENV{PATH} = join ':', realpath(rel2abs($opts{nginx_objdir})),
      $ENV{PATH};

    if ($opts->{prove_command}) {
        verbose("Using custom prove command: `$opts->{prove_command}`");
        verbose("Ignoring test-sources: @{$opts->{test_sources}}");

        system $opts->{prove_command}
          and die "$opts->{prove_command} failed\n";

        return;
    }

    eval { require App::Prove }
      or die "Please install App::Prove:\n"
      . "     curl -L http://cpanmin.us | perl - App::Prove\n";

    verbose("Using App::Prove v${App::Prove::VERSION}");
    verbose("Using test-sources: @{$opts->{test_sources}}");

    # It's usual for tests to expect working dir is package dir
    my $working = getcwd;
    {
        chdir $opts->{module_dir};

        # I don't care here if any test fails
        system 'prove', '-lmr', @{$opts->{test_sources}};
    };
    chdir $working;

    foreach my $src (@$sources) {
        $src = abs2rel($src, $opts->{module_dir});
        my $gcno = catfile($opts->{nginx_objdir}, 'addon', $src);
        $gcno =~ s/\.c$/.gcno/;
        system 'gcov', '-p', $opts->{module_dir}, '-o',
          dirname($gcno), $gcno;
    }

    my @gcov = grep { -f $_ } <*.gcov>;
    system 'gcov2perl', @gcov and die "gcov2perl failed\n";
    system 'cover';
}

sub find_sources {
    my ($dir) = @_;
    my @sources;
    find(
        {   no_chdir => 1,
            wanted   => sub {
                return unless /\.c$/;
                my $srcname = rel2abs($_, $dir);
                push @sources, $srcname;
              }
        },
        $dir
    );
    @sources = map { realpath($_) } @sources;
    return @sources;
}

sub make_nginx {
    my ($opts, $sources) = @_;
    verbose("Setting up makefile $opts->{nginx_makefile}");

    my $make = slurp($opts->{nginx_makefile});
    if ($make !~ /-lgcov/) {
        die
          "Makefile '$opts->{nginx_makefile}' is not configured with '--with-ld-opt=-lgcov'.\n"
          . "Please reconfigure.\n";
    }
    else {
        verbose("Nginx configured --with-ld-opt=-lgcov");

        # TODO: reconfigure with opts from ./objs/ngx_auto_config.h
    }
    $make .= "\n\ncover:\n";
    foreach my $src (@$sources) {
        my $objname = abs2rel($src, $opts->{module_dir});
        ($objname) = no_upwards($objname);
        $objname =~ s/\.c$/.o/;
        $make
          .= '	$(CC) -c $(CFLAGS) -fprofile-arcs -ftest-coverage $(ALL_INCS)';
        $make .= " -o objs/addon/$objname $src\n";
    }

    my $MAKE_COVER = File::Temp->new(TEMPLATE => 'Makefile-XXXXXX');
    print $MAKE_COVER $make;
    close $MAKE_COVER;

    verbose("Remove old coverage files");
    find(
        {   no_chdir => 1,
            wanted   => sub {
                return unless /\.(?:gcno|gcda)$/;
                unlink($_) or die "Failed to remove file '$_': $!";
              }
        },
        $opts->{nginx_dir}
    );
    my @gcov = grep { -f $_ } <*.gcov>;
    unlink(@gcov) if @gcov;
    remove_tree('cover_db') if -d 'cover_db';
    if (-f $opts{nginx_bin}) {
        verbose("Remove old nginx");
        unlink($opts{nginx_bin})
          or die "Failed to remove $opts{nginx_bin}: $!";
    }

    my $makefile = rel2abs($MAKE_COVER->filename);
    system('make', '-C', $opts->{nginx_dir}, '-f', $makefile, 'cover')
      and die "Failed to make cover\n";

    system('make', '-C', $opts->{nginx_dir}, '-f', $makefile)
      and die "Failed to make nginx\n";
}

sub check_opts {
    my ($opts) = @_;

    eval { require Devel::Cover }
      or die "Please install Devel::Cover:\n"
      . "     curl -L http://cpanmin.us | perl - Devel::Cover\n";

    verbose("Using Devel::Cover v${Devel::Cover::VERSION}");

    if (!-d $opts->{nginx_dir}) {
        die "Nginx dir '$opts->{nginx_dir}' does not exist.\n";
    }
    else {
        verbose("Nginx dir '$opts->{nginx_dir}' exists");
    }

    if (!-f $opts->{nginx_makefile}) {
        die
          "No makefile found: '$opts->{nginx_makefile}'. Forgot to ./configure ?\n";
    }
    else {
        verbose("Nginx Makefile '$opts->{nginx_makefile}' exists");
    }

    if (!-d $opts->{module_dir}) {
        die "Nginx module dir '$opts->{module_dir}' does not exist.\n";
    }
    else {
        verbose("Module dir '$opts->{module_dir}' exists");
    }
}

sub verbose {
    return unless $opts{verbose};
    print basename($0), ": ", @_, "\n";
}

sub slurp {
    local $/;
    open my $M, $_[0] or Carp::croak("Failed to read file '$_[0]': $!");
    <$M>;
}


__END__

=head1 NAME

ngx_coverage.pl - produces test coverage for nginx third-party modules

=head1 SYNOPSIS

ngx_coverage.pl [options] <nginx dir>

    Options:
    --help            brief help message
    --module-dir      module directory
    --test-source     't' by default
    --prove-command   custom prove command
    --verbose         detailed output

=head1 OPTIONS

=over 8

=item B<--help>

Print a brief help message and exits.

=item B<--module-dir>

A dir with module to cover. Defaults to current working dir.

=item B<--module-sources>

A dir that contains module sources. Relative to a module dir. Defaults to 'src'.

=item B<--test-source>

Test source for prove. Defaults to 't' dir in a module dir.
Multiple test sources are supported.

=item B<--prove-command>

A command to use instead of standard prove. Ignores L<--test-source>.

=back

=head1 DESCRIPTION

B<make_coverage.pl> collects test coverage of your module
and provides detailed information in HTML format.

=cut
