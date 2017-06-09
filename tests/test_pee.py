#    peepdf is a tool to analyse and modify PDF files
#    http://peepdf.eternal-todo.com
#    By Jose Miguel Esparza <jesparza AT eternal-todo.com>
#
#    Copyright (C) 2016 Jose Miguel Esparza
#
#    This file is part of peepdf.
#
#        peepdf is free software: you can redistribute it and/or modify
#        it under the terms of the GNU General Public License as published by
#        the Free Software Foundation, either version 3 of the License, or
#        (at your option) any later version.
#
#        peepdf is distributed in the hope that it will be useful,
#        but WITHOUT ANY WARRANTY; without even the implied warranty of
#        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
#        GNU General Public License for more details.
#
#        You should have received a copy of the GNU General Public License
#        along with peepdf.    If not, see <http://www.gnu.org/licenses/>.
#

import mock
import peepdf
import peepdf.main
import pytest

def test_js_detect():
    p = peepdf.PDFCore.PDFParser()
    r, f = p.parse(
        "tests/files/js_in_pdf.js", forceMode=True,
        looseMode=True, manualAnalysis=False
    )
    assert not r

    ret = []
    js_found = 0

    for version in xrange(f.updates + 1):
        for obj in f.body[version].objects.values():
            if isinstance(obj, peepdf.PDFCore.PDFIndirectObject):
                o = obj.getObject()
                if isinstance(o, peepdf.PDFCore.PDFStream):
                    stream = o.decodedStream
                    isJS = peepdf.JSAnalysis.isJavascript(stream)
                    if "function docOpened()" in stream:
                        assert isJS
                    else:
                        assert not isJS

def test_whitespace_after_opening():
    p = peepdf.PDFCore.PDFParser()
    r, f = p.parse(
        "tests/files/BB-1-Overview.pdf",
        forceMode=True, looseMode=True, manualAnalysis=False
    )
    assert not r

    for obj in f.body[1].objects.values():
        if obj.object.type == "stream":
            assert obj.object.errors != [
                "Decoding error: Error decompressing string"
            ]

def test_lxml_missing():
    with mock.patch.dict(peepdf.main.__dict__, {"etree": None}):
        with pytest.raises(AssertionError) as e:
            peepdf.main.getPeepXML(None, None, None)
        e.match("lxml must be installed")
