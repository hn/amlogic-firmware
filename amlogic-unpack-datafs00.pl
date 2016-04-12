#!/usr/bin/perl
#
# amlogic-unpack-datafs00.pl, V1.04
#
# Unpack files from Amlogic's DATAFS00 archive (AVOS update file)
#
# (C) 2012 Hajo Noerenberg
#
# http://www.noerenberg.de/
# https://github.com/hn/amlogic-firmware
#
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 3.0 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program. If not, see <http://www.gnu.org/licenses/gpl-3.0.txt>.
#

use strict;

my $debug=1;

my $f=$ARGV[0];
my $d=$ARGV[1];

my ($lookup_pos, $lookup_len);
my ($data_pos, $data_len);
my ($name_pos, $name_len);

sub rb {
  my ($buf, $t);
  my ($p, $l) = @_;

  seek(FS, $p, 0);
  read(FS, $buf, $l);
  $a=$buf;
  $a=~s/[^[:print:]]+/./g;;
  print "Reading " . sprintf("%6d", $l) . " bytes at offset " . sprintf("%7d", $p) . ": 0x" . sprintf("%-32s", unpack("H*", substr($buf, 0, 16))) . " (a '" . substr($a, 0, 16) . "') \n" if($debug);
  return $buf;
}

sub rl {
  my ($buf, $n);
  my ($p, $l) = @_;

  seek(FS, $p, 0);
  read(FS, $buf, $l);
  $n=unpack("L<*", $buf);
  print "Reading " . sprintf("%6d", $l) . " bytes at offset " . sprintf("%7d", $p) . ": 0x" . sprintf("%-32s", unpack("H*",$buf)) . " (l " . $n . ")\n" if ($debug);
  return $n;
}

print ("Usage: $0 <datafs00-file> <output-dir>\n"), exit 1 if (!$d);
open (FS, "<$f") || die("Unable to open '$f': " . $!);

print ("Invalid magic\n"), exit 1 if (rb(0, 8) ne "DATAFS00");
print ("Invalid EOT\n"), exit 1 if (rb(508, 4) ne "\xAA\x55\xAA\x55");

$lookup_pos=rl(16, 4);
$lookup_len=rl(20, 4);
$data_pos=rl(24, 4);
$data_len=rl(28, 4);
$name_pos=rl(32, 4);
$name_len=rl(36, 4);

print "lookup table pos: $lookup_pos, len: $lookup_len\n";
print "name table   pos: $name_pos, len: $name_len\n";
print "data table   pos: $data_pos, len: $data_len\n";

for (my $e=$lookup_pos; $e<$lookup_pos+$lookup_len; $e+=32) {
  print "\nlookup table pos $e:\n";
  my $fn_pos=rl($e+16, 4);
  my $fn_len=rl($e+20, 4);
  my $d_pos=rl($e+8, 4);
  my $d_len=rl($e+12, 4);
  my $mtime=rl($e+4, 4);
  my $fn=rb($name_pos + $fn_pos, $fn_len);
  $fn=~s/\x00//g;
  $fn=~s/[^a-z0-9_. -]/^/gi;
  print "Unpacking file '$fn'\n";

  open(OF, ">" . $d . "/" . $fn) || die("Unable to open output file: " . $!);
  print OF rb($data_pos + $d_pos, $d_len);
  close(OF);
  utime(undef, $mtime, $d . "/" . $fn);
}

close (FS);

