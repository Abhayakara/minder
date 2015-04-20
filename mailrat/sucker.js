#!/usr/bin/env node

// Requirements
var fs = require('fs');
var sys = require('sys');
var readline = require('./readline');

// Where we are getting the files from...
var dir = '/home/mellon/mail/cur'

// A dictionary with one entry per file scanned.   Each entry is a dictionary
// of two elements: headerFieldContents and headerFieldIndices.
//
// headerFieldContents is an array containing each header field's contents
// in sequence (the header field name is not stored).
//
// headerFieldIndices is a dictionary indexed by header field name.   Each
// entry in the dictionary is an array containing the indices into
// headerFieldContents for each of the header fields whose name is the
// dictionary key.

var fileHeaders = {};

// Read all the files in dir, parsing headers out of each file.
fs.readdirSync(dir).forEach(function(filename) {
  var headers = [];
  var indices = {};
  var numHeaders = 0;

  // Function to grok a single header and stash its contents into
  // the headers and indices variables.
  var grokHeader = function(header) {
    var off = header.indexOf(":");
    if (off != -1) {
      var headerFieldName = header.substring(0, off).toLowerCase();
      var headerContent = header.substring(off + 1).trimLeft(' \t');
      
      headers[numHeaders] = headerContent;
      if (indices.hasOwnProperty(headerFieldName)) {
	indices[headerFieldName].push(numHeaders);
      } else {
	indices[headerFieldName] = [numHeaders];
      }
      numHeaders++;
  } };

    var accum = null;
    readline.readlines(dir + "/" + filename, function(line) {
	var done = false;
	if (line == '') {
	    done = true;
	    if (accum != null)
		grokHeader(accum);
	    accum = null;
	} else {
	    if (line[0] == ' ' || line[0] == '\t') {
		accum += line;
	    } else {
		if (accum != null)
		    grokHeader(accum);
		accum = line;
	    }}
	return done;
    });

  fileHeaders[filename] = { 'headerFieldContents': headers,
			    'headerFieldIndices': indices };
});

var subjects = {};
var counts = {};
for (var filename in fileHeaders) {
  headers = fileHeaders[filename];
  indices = headers['headerFieldIndices'];
  contents = headers['headerFieldContents'];
  if (indices.hasOwnProperty('message-id')) {
    var subjectHeaders = indices['message-id'];
    for (var i = 0; i < subjectHeaders.length; i++) {
      var headerContent = contents[subjectHeaders[i]];
      if (subjects.hasOwnProperty(headerContent)) {
	subjects[headerContent].push(filename);
	counts[headerContent]++;
      } else {
	subjects[headerContent] = [filename];
	counts[headerContent] = 1;
} } } }

var heights = [];

for (var key in counts) {
  if (counts.hasOwnProperty(key)) {
    if (heights.hasOwnProperty(counts[key])) {
      heights[counts[key]].push(key);
    } else {
      heights[counts[key]] = [key];
} } }

var dumped = 0;
for (var i = heights.length - 1; i >= 0; i--) {
  if (heights[i] != undefined) {
    for (j = 0; j < heights[i].length; j++) {
      sys.print(i.toString() + ": " + heights[i][j] + "\n");
     dumped++;
      if (dumped > 40)
	break;
    }
    if (dumped > 40)
      break;
} }
