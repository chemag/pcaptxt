Quick Description

Usage Notes

Installation Notes
	- .vimrc


# installation notes (user)

0. pre-installation requisites
- you need flex
- you must compile libpcap from sources (static)

1. get the source code
```
$ git clone https://github.com/chemag/pcaptxt.git
```

2. build and install binary
```
$ cd pcaptxt/
$ ./configure
```
-- note: make sure `-O0` is set (otherwise txt->pcap is broken)
```
$ make && sudo make install
```

3. run tests [optional]
```
$ make test
```

4. copy ./scripts/pcap.vim into ~/.vim/plugin/ directory
```
$ cp ./scripts/pcap.vim ~/.vim/plugin/
```

5. check that opening a .pcap file using vim allows text-based pcap trace
edition
```
$ vi file.pcap
```

# package management (maintainer)

- re-create package
  - autoreconf
- clean everything
  - make maintainer-clean
- create dist
  - ./configure
  - make dist

