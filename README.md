# mysqldumper

This is a python script that allows you to dump a mysql databse. If you ever find yourself having to use sql quries to traverse a whole db and hunt for potential info then this is for you : )

I use this script to dump the contents of the tables and non default DBs into a text file that can allow you to easily open in your text editor and then use crtl f to search for interesting info. It also tries to point out interesting information via string search

It can work both locally, where the mysql instance is running on the local system or on a remote system. It will first attempt to connect via root and no password; before interactively prompting you to either use root with a password you provide or use a different username/passwd combo

Note that this does not do any analyse or hunting for you; it is mainly meant to dump the contents of a mysql instance into a nicely formated text file to allow convient traversal in a text editor
