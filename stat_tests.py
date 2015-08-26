#!/usr/bin/python
#
#    peepdf is a tool to analyse and modify PDF files
#    http://peepdf.eternal-todo.com
#    By Jose Miguel Esparza <jesparza AT eternal-todo.com>
#
#    Copyright (C) 2011-2015 Jose Miguel Esparza
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

'''
     Get PDF score stats with samples
     USED ONLY FOR TESTING PURPOSES( not required for working peepdf)
'''

import PDFCore
import PDFGlobals
import argparse
import sys
import os
import signal
import gc


interruptCaught = False


def sigint_handler(signal, frame):
    # Pack Up stats with whatever files analyzed
    global interruptCaught
    interruptCaught = True

signal.signal(signal.SIGINT, sigint_handler)


def restart_line():
    sys.stdout.flush()
    sys.stdout.write('\r' + ' '*150 + '\r')
    sys.stdout.flush()


def format(d, tab=0, level=0):
    # Format into json with arrays/lists in single line
    s = ['{\n']
    localTab = tab + tab*level
    for k,v in d.items():
        if isinstance(v, dict):
            v = format(v, tab, level+1)
        else:
            v = repr(v)
        s.append('%s%r: %s,\n' % ('  '*localTab, k, v))
    s.append('%s}' % ('  '*(localTab-tab)))
    return ''.join(s)


def packUp(stats, args):
    # Packup the testing and write results to file.
    if not args.silent:
        restart_line()
    # Calculate Percentages
    stats['numRawScoreGreaterThanThreshold'][1] = round((float(stats['numRawScoreGreaterThanThreshold'][0])/float(stats['numAnalyzedFiles']))  * 100.0, 2)
    for scoreStatsKey in stats['scoreStats']:
        stats['scoreStats'][scoreStatsKey][1] = round((float(stats['scoreStats'][scoreStatsKey][0])/float(stats['numAnalyzedFiles'])) * 100.0, 2)
    stats['numExceptionFiles'][1] = round((float(stats['numExceptionFiles'][0])/float(stats['numAnalyzedFiles'])) * 100.0, 2)
    for indicatorStatsKey in stats['indicatorStats']:
        stats['indicatorStats'][indicatorStatsKey][1] = round((float(stats['indicatorStats'][indicatorStatsKey][0])/float(stats['numAnalyzedFiles'])) * 100.0, 2)
    jsonDict = format(stats, tab=4)
    if args.output is not None:
        f = open(args.output, 'w')
        f.write(jsonDict)
        f.close()
        if not args.silent:
            print "Detailed stats saved at %s" %args.output
    if not args.silent:
        print format(stats, tab=4)


def freeMemory(*args):
    for obj in args:
        del obj
    gc.collect()


def main():
    global interruptCaught
    parser =  argparse.ArgumentParser(description='Run peepdf on PDF files in a directory and get stats.')
    parser.add_argument('-d', '--directory', action='store', type=str,
                      help='Test pdf files from this directory')
    parser.add_argument('-c', '--check-vt', action='store_true', default=False, dest='checkonVT',
                      help='Check the hash of the PDF files on VirusTotal too.(SLOW)')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--clean', action='store_true', default=False,
                     help='Assume directory contains clean files')
    group.add_argument('--malicious', action='store_true', default=False,
                     help='Assume directory contains malicious files')
    group.add_argument('--unknown', action='store_true', default=False,
                     help='Assume directory contains mixed files')
    parser.add_argument('-s', '--silent', action='store_true', default=False,
                             help='Silently write to OUTPUT file and exit')
    parser.add_argument('-o', '--output', action='store', type=str,
                             help='Filename to save stats in json format')
    args = parser.parse_args()
    if args.silent and args.output is None:
         parser.error( 'argument -o/--output is required if using argument -s/--silent' )
         sys.exit()
    directory = args.directory
    isForceMode = True
    isLooseMode = True
    isManualAnalysis = False
    checkonVT = args.checkonVT
    version = PDFGlobals.version
    revision = PDFGlobals.revision
    if args.clean:
        userDefinedStatus = 'clean'
    elif args.malicious:
        userDefinedStatus = 'malicious'
    elif args.unknown:
        userDefinedStatus = 'unknown'
    if not os.path.isabs(directory):
        directory = os.path.join(os.getcwd(), directory)
    files = os.listdir(directory)
    numAnalyzedFiles = 0
    stats = {
        # Array indicates [numberOfOccurrences, Percentage]
        'numFiles': len(files),
        'numAnalyzedFiles': numAnalyzedFiles,
        'userDefinedStatus': userDefinedStatus,
        'numRawScoreGreaterThanThreshold': [0, 0.0],
        'directory': directory,
        'scoreStats': {
            '0-1': [0, 0.0],
            '1-2': [0, 0.0],
            '2-3': [0, 0.0],
            '3-4': [0, 0.0],
            '4-5': [0, 0.0],
            '5-6': [0, 0.0],
            '6-7': [0, 0.0],
            '7-8': [0, 0.0],
            '8-9': [0, 0.0],
            '9-10': [0, 0.0],
            '10': [0, 0.0]
        },
        'numExceptionFiles': [0, 0.0],
        'indicatorStats': {}
    }
    numFiles = len(files)
    numExceptions = 0
    if args.output:
        individualStatsFileName = args.output + '_files'
        individualStatsFile = open(individualStatsFileName, 'w')
        individualStatsFile.close()
        individualStatsFile = open(individualStatsFileName, 'a')
        exceptionsFileName = args.output + '_exceptions'
        exceptionsFile = open(exceptionsFileName, 'w')
        exceptionsFile.close()
        exceptionsFile = open(exceptionsFileName, 'a')
    for index, filename in enumerate(files):
        if interruptCaught:
            if not args.silent:
                restart_line()
                print "\rInterrupt Caught. Packing Up with %s/%s Analyzed Files." %(index, numFiles)
            break
        if not args.silent:
            restart_line()
            sys.stdout.write('\rExceptions(errors): %s| %s/%s: Analyzing %s' %(numExceptions, index+1, numFiles, filename))
            sys.stdout.flush()
        filePath = os.path.join(directory, filename)
        fileSize = os.path.getsize(filePath)
        exception = None
        exceptionData = None
        if fileSize > 999999:
            # Skipping very large files
            continue
        pdfParser = PDFCore.PDFParser()
        try:
            ret, pdf = pdfParser.parse(filePath, isForceMode, isLooseMode, isManualAnalysis, checkonVT)
            statsDict = pdf.getStats()
            scoringFactors = pdf.getScoringFactors(nonNull=True)
        except Exception, e:
            stats['numExceptionFiles'][0] += 1
            exception = {}
            exception['filePath'] = filePath
            exception['exception'] = e
            exceptionData = format(exception, tab=4)
            exceptionsFile.write(exceptionData)
            exceptionsFile.flush()
            numExceptions += 1
            continue
        score = pdf.score
        intScore = int(score)
        scoreStatsKey = str(intScore) + '-' + str(intScore+1)
        if scoreStatsKey == '10-11':
            scoreStatsKey = '10'
        stats['scoreStats'][scoreStatsKey][0] += 1
        if pdf.rawScore > pdf.thresholdScore:
            stats['numRawScoreGreaterThanThreshold'][0] += 1
        for factor in scoringFactors:
            if factor not in stats['indicatorStats'].keys():
                stats['indicatorStats'][factor] = [1, 0]
            else:
                stats['indicatorStats'][factor][0] += 1
        fileData = {}
        fileData['filePath'] = filePath
        fileData['score'] = round(pdf.score, 3)
        fileData['rawScore'] = pdf.rawScore
        fileData['thresholdScore'] = pdf.thresholdScore
        fileData['md5'] = pdf.md5
        fileData['index'] = index+1
        fileDataFormatted = format(fileData, tab=4)
        individualStatsFile.write(fileDataFormatted)
        individualStatsFile.flush()
        numAnalyzedFiles += 1
        stats['numAnalyzedFiles'] = numAnalyzedFiles
        freeMemory(pdfParser, pdf, ret, fileData, exception, exceptionData, fileDataFormatted)
    packUp(stats, args)


if __name__ == '__main__':
    sys.exit(main())
