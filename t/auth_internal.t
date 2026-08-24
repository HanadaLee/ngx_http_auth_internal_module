#!/usr/bin/perl

# Tests for ngx_http_auth_internal_module.

###############################################################################

use warnings;
use strict;

use Digest::MD5 qw/md5_hex/;
use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http rewrite ngx_condition_module
	ngx_http_auth_internal_module/)->plan(12);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  protected.local;

        auth_internal on;
        auth_internal_secret primary;
        auth_internal_secret rotated;
        auth_internal_empty_deny on;
        auth_internal_failure_deny on;
        auth_internal_timeout 60s;

        location / {
            return 200 "$auth_internal_result";
        }
    }

    server {
        listen       127.0.0.1:8080;
        server_name  relaxed.local;

        auth_internal on;
        auth_internal_secret primary;
        auth_internal_empty_deny off;
        auth_internal_failure_deny off;
        auth_internal_timeout 60s;

        location / {
            return 200 "$auth_internal_result";
        }
    }

    server {
        listen       127.0.0.1:8080;
        server_name  conditional.local;

        condition bypass str_eq $http_x_auth_mode bypass;
        condition alternate str_eq $http_x_auth_mode alternate;

        when bypass {
            auth_internal off;
        }
        auth_internal on;

        when alternate {
            auth_internal_secret alternate;
        }
        auth_internal_secret primary;

        auth_internal_empty_deny on;
        auth_internal_failure_deny on;
        auth_internal_timeout 60s;

        location / {
            return 200 "$auth_internal_result";
        }
    }

    server {
        listen       127.0.0.1:8080;
        server_name  custom-header.local;

        auth_internal on;
        auth_internal_secret primary;
        auth_internal_empty_deny on;
        auth_internal_header X-Internal-Token;

        location / {
            return 200 "$auth_internal_result";
        }
    }
}

EOF

$t->run();

###############################################################################

sub fingerprint {
	my ($secret, $timestamp) = @_;
	my $hex = sprintf('%08x', $timestamp);

	return $hex . md5_hex($secret . $hex);
}

sub request {
	my ($host, %headers) = @_;
	my $request = "GET / HTTP/1.0\r\nHost: $host\r\n";

	for my $name (sort keys %headers) {
		$request .= "$name: $headers{$name}\r\n";
	}

	return http($request . "\r\n");
}

my $now = time();
my $primary = fingerprint('primary', $now);
my $rotated = fingerprint('rotated', $now);
my $alternate = fingerprint('alternate', $now);
my $expired = fingerprint('primary', $now - 3600);

like(request('protected.local', 'X-Fingerprint' => $primary),
	qr/200 OK.*\x0d\x0a\x0d\x0asuccess$/s, 'primary secret succeeds');
like(request('protected.local', 'X-Fingerprint' => $rotated),
	qr/200 OK.*\x0d\x0a\x0d\x0asuccess$/s, 'rotated secret succeeds');
like(request('protected.local'), qr/403 Forbidden/,
	'missing fingerprint is denied');
like(request('protected.local', 'X-Fingerprint' => 'invalid'),
	qr/403 Forbidden/, 'malformed fingerprint is denied');
like(request('protected.local', 'X-Fingerprint' => $expired),
	qr/403 Forbidden/, 'expired fingerprint is denied');
like(request('protected.local', 'X-Fingerprint' => fingerprint('wrong', $now)),
	qr/403 Forbidden/, 'wrong secret is denied');

like(request('relaxed.local'),
	qr/200 OK.*\x0d\x0a\x0d\x0aempty$/s,
	'missing fingerprint can be observed without denial');
like(request('relaxed.local', 'X-Fingerprint' => 'invalid'),
	qr/200 OK.*\x0d\x0a\x0d\x0afailure$/s,
	'invalid fingerprint can be observed without denial');

like(request('conditional.local', 'X-Auth-Mode' => 'bypass'),
	qr/200 OK.*\x0d\x0a\x0d\x0aoff$/s,
	'matching condition disables authentication');
like(request('conditional.local', 'X-Auth-Mode' => 'alternate',
	'X-Fingerprint' => $alternate),
	qr/200 OK.*\x0d\x0a\x0d\x0asuccess$/s,
	'matching condition selects alternate secret');
like(request('conditional.local', 'X-Auth-Mode' => 'other',
	'X-Fingerprint' => $primary),
	qr/200 OK.*\x0d\x0a\x0d\x0asuccess$/s,
	'condition miss uses unconditional fallback');
like(request('custom-header.local', 'X-Internal-Token' => $primary),
	qr/200 OK.*\x0d\x0a\x0d\x0asuccess$/s,
	'custom fingerprint header is honored');

###############################################################################
