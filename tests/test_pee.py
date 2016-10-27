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

import peepdf

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
