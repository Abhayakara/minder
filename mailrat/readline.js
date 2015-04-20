// Given a filename, open the file and read it, calling lineHandler for
// each line in the file.   If lineHandler returns true, continue; otherwise,
// stop.

var sys = require('sys');
var fs = require('fs');

exports.readlines = function(filename, lineHandler) {
    var stream = fs.openSync(filename, "r");
    var buffer = new Buffer(4096);
    var len = 0;
    var off = 0;
    var done = false;
    var blocks = 0;
    
    var remainder = null;
    
    // Loop through the file, 4096 bytes at a time
    while (!done) {
	len = fs.readSync(stream, buffer, 0, 4096, null);
	off = 0;
	if (len != 0) {
	    blocks = blocks + 1;
	    var str = buffer.toString('ascii');
	    if (remainder != null)
		str = remainder + str;
	    
	    while (off != -1) {
		var next = str.indexOf('\n', off);
		if (next != -1) {
		    var line = str.substring(off, next);
		    next++;
		    done = lineHandler(line);
		} else {
		    remainder = str.substring(off);
		}
		off = next;
	    }}
	else {
	    done = true;
	}}
    fs.closeSync(stream);
};
