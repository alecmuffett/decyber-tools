/*
Copyright (c) 2012, Alec.Muffett@gmail.com All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

- Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.

- Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.

- Neither the name of the <organization> nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT
HOLDER> BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

var replacements = [
    [ /\bAPT\b/g, "malicious hackers"],
    [ /\bAnonymous\b/g, "Someone"],
    [ /\bCyber.?[Ss]ecurity\b/g, "Internet Security"],
    [ /\bCyber.?space\b/g, "The internet"],
    [ /\bzero.?day.vulnerability\b/gi, "brand new bug"],
    [ /\btrusted\b/gi, "reasonably trustworthy"],
    [ /\bsurfing\b/gi, "browsing"],
    [ /\bskimming\b/gi, "fraud"],
    [ /\bsecure\scyberspace\b/gi, "secure internet"],
    [ /\bintellectual.property\b/gi, "documents"],
    [ /\bidentity.?theft\b/gi, "fraud"],
    [ /\bidentity.?ecosystem\b/gi, "id-card"],
    [ /\bcyber\sand\b/gi, ""],
    [ /\bcyber.?threat\b/gi, "risk of being connected to the internet"],
    [ /\bcyber.?space\b/gi, "the internet"],
    [ /\bcyber.?security\b/gi, "internet security"],
    [ /\bcyber.?geddon\b/gi, "disaster"],
    [ /\bcyber.?espionage\b/gi, "espionage"],
    [ /\bcyber.?attacks\b/gi, "illegal hacking"],
    [ /\bcyber-?/gi, ""],
    [ /\badvanced.?persistent.?threats?\b/gi, "malicious hackers"],
    [ /\b0.?day\b/gi, "new bug"],
    [ /\b0.?days\b/gi, "new bugs"],
];

var decyber = function (input) {
    var i, output, replacement;
    output = input;
    for (i = 0; i < replacements.length; i++) {
	replacement = replacements[i];
	output = output.replace(replacement[0], replacement[1]);
    }
    // alert(input + " => " + output);
    return output;
};

var decyberTree = function (node) {
    var i, n, children;

    // depth first
    if (node.hasChildNodes()) {
	children = node.childNodes;
	for (i = 0; i < children.length; i++) {
	    decyberTree(children[i]);
	}
    }

    // then self
    if (node.nodeType == 3) {
	n = decyber(node.nodeValue);
	node.nodeValue = n;
    }
}

var decyberAllSelectedNodes = function () {
    var i, selection, range, ranges;

    selection = window.getSelection();
    ranges = [];

    // type 3 -> TEXT_NODE
    for (i = 0; i < selection.rangeCount; i++) {
	range = selection.getRangeAt(i);
	while(range.startContainer.nodeType == 3 || range.startContainer.childNodes.length == 1)
	    range.setStartBefore(range.startContainer);
	while(range.endContainer.nodeType == 3 || range.endContainer.childNodes.length == 1)
	    range.setEndAfter(range.endContainer);
	ranges.push(range);
    }

    // filter them
    for (i = 0; i < ranges.length; i++) {
	range = ranges[i];
	decyberTree(range.commonAncestorContainer);
    }
};
