

==========
e2ksniffer
==========
A statefull and real-time traffic sniffer for edonkey p2p network
-----------------------------------------------------------------


Introduction
============


Long story sort, during my masters I developed this thing. It was meant to
monitor traffic in an ISP for traffic related to the `eDonkey Network`_ (e2k)
and perform the following actions on the traffic:

 * Log e2k transactions (downloads, queries etc).

 * Gather information about files being transfered and their progress.

 * Collect data related to transferred files in order. Such data would
   later be fed into a cache for a L4/L7 proxy. While the data
   colection code is here, the proxy/cache code is not.


Updates, fixes and other things I won't do
------------------------------------------

This code is pretty ancient hystory and I have no intent on maintaining
it. I am publish it just for the sake of making it available to others.
Who knows, some one might find it interesting or useful.


Building it
===========


Well, head to ``src`` directory, adjust ``Makefile`` as you see fit, light a
candle, invoke `make` and hope for the best. I haven't touched this code for +4
years -- all I know is that once upon a time a simple ``make`` would do.


Dependencies
============

This code depends on libNIDS_ and zlib_.


License
=======

LibNIDS_ is GPL and thus so are we. :) Additionaly, this code was heavily based
on the behaviour presented by eMule_ and aMule_ clients and their source codes.
Since both are also GPL'ed, once again, so are we.

Read COPYING for the whole thing.




.. _libNIDS: http://libnids.sourceforge.net/
.. _`eDonkey Network`: http://en.wikipedia.org/wiki/EDonkey_network
.. _eMule: http://www.emule-project.net/
.. _zlib: http://zlib.net
.. _aMule: http://www.amule.org
