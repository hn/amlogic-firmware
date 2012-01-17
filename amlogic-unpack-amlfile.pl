#!/usr/bin/perl
#
# amlogic-unpack-amlfile.pl, V1.01
#
# Unpack files from Amlogic's AML firmware archive (AVOS update file)
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

sub rb {
  my ($buf, $t);
  my ($p, $l) = @_;

  seek(FS, $p, 0);
  read(FS, $buf, $l);
  $t=$buf;
  $t=~s/[^[:print:]]+/./g;;
  print "Reading " . sprintf("%6d", $l) . " bytes at offset " . sprintf("%7d", $p) . ": 0x" . sprintf("%-32s", unpack("H*", substr($buf, 0, 16))) . " (a '" . substr($t, 0, 16) . "') \n" if($debug);
  return $buf;
}

sub rl {
  my ($buf, $n);
  my ($p, $l) = @_;

  seek(FS, $p, 0);
  read(FS, $buf, $l);
  $buf.="\x00" if ($l==3);
  $buf.="\x00\x00\x00" if ($l==1);
  $n=unpack("L<*", $buf);
  print "Reading " . sprintf("%6d", $l) . " bytes at offset " . sprintf("%7d", $p) . ": 0x" . sprintf("%-32s", unpack("H*",$buf)) . " (l " . $n . ")\n" if ($debug);
  return $n;
}

print "\nBETA UNPACKER -- INCOMPLETE\n\n";

print ("Usage: $0 <aml-file> <output-dir>\n"), exit 1 if (!$d);
open (FS, "<$f") || die("Unable to open '$f': " . $!);

print ("Invalid magic\n"), exit 1 if (rb(0, 4) ne " LMA");

for (my $i=0; $i<1234; $i++) {
  print "\nchunk table entry $i:\n";
  my $d_pos=rl(100+$i*20+0, 4);
  my $d_typ=rl(100+$i*20+4+3, 1);
  my $d_len=rl(100+$i*20+4, 3);
  my $m_adr=rl(100+$i*20+8, 4);		# dst mem address ?
  my $m_len=rl(100+$i*20+12, 4);	# dst mem length, zero fill ?
#  my $d_chk=rb(100+$i*20+16, 4);	# checksum ?

  if ($d_typ!=0 && $d_typ!=32) {
    print "Skipping unknown chunk type $d_typ\n";	# ?
    next;
  }
  last if ($d_len==0);

  print "Unpacking chunk '$i'\n";

  open(OF, ">" . $d . "/chunk-" . sprintf("%03d", $i) . "-" . sprintf("%.8X", $m_adr) . "-" . sprintf("%.8X",$m_len)) || die("Unable to open output file: " . $!);
  print OF rb($d_pos, $d_len);
  close(OF);
}

close (FS);

