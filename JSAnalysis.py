#
#    peepdf is a tool to analyse and modify PDF files
#    http://peepdf.eternal-todo.com
#    By Jose Miguel Esparza <jesparza AT eternal-todo.com>
#
#    Copyright (C) 2011-2017 Jose Miguel Esparza
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
    This module contains some functions to analyse Javascript code inside the PDF file
'''

import jsbeautifier
import os
import re
import sys
import traceback

from PDFUtils import unescapeHTMLEntities, escapeString

try:
    import PyV8
    
    JS_MODULE = True
    
    class Global(PyV8.JSClass):
        evalCode = ''
        
        def evalOverride(self, expression):
            self.evalCode += '\n\n// New evaluated code\n' + expression
            return
        
except:
    JS_MODULE = False


errorsFile = 'errors.txt'
newLine = os.linesep         
reJSscript = '<script[^>]*?contentType\s*?=\s*?[\'"]application/x-javascript[\'"][^>]*?>(.*?)</script>'
preDefinedCode = 'var app = this;'


def analyseJS(code, context=None, manualAnalysis=False):
    '''
        Hooks the eval function and search for obfuscated elements in the Javascript code
        
        @param code: The Javascript code (string)
        @return: List with analysis information of the Javascript code: [JSCode,unescapedBytes,urlsFound,errors,context], where 
                JSCode is a list with the several stages Javascript code,
                unescapedBytes is a list with the parameters of unescape functions, 
                urlsFound is a list with the URLs found in the unescaped bytes,
                errors is a list of errors,
                context is the context of execution of the Javascript code.
    '''
    errors = []
    jsCode = []
    unescapedBytes = []
    urlsFound = []
    
    try:
        code = unescapeHTMLEntities(code)
        scriptElements = re.findall(reJSscript, code, re.DOTALL | re.IGNORECASE)
        if scriptElements:
            code = ''
            for scriptElement in scriptElements:
                code += scriptElement + '\n\n'
        code = jsbeautifier.beautify(code)
        jsCode.append(code)
    
        if code is not None and JS_MODULE and not manualAnalysis:
            if context is None:
                context = PyV8.JSContext(Global())
            context.enter()
            # Hooking the eval function
            context.eval('eval=evalOverride')
            #context.eval(preDefinedCode)
            while True:
                originalCode = code
                try:
                    context.eval(code)
                    evalCode = context.eval('evalCode')
                    evalCode = jsbeautifier.beautify(evalCode)
                    if evalCode != '' and evalCode != code:
                        code = evalCode
                        jsCode.append(code)
                    else:
                        break
                except:
                    error = str(sys.exc_info()[1])
                    open('jserror.log', 'ab').write(error + newLine)
                    errors.append(error)
                    break
            
            if code != '':
                escapedVars = re.findall('(\w*?)\s*?=\s*?(unescape\((.*?)\))', code, re.DOTALL)
                for var in escapedVars:
                    bytes = var[2]
                    if bytes.find('+') != -1 or bytes.find('%') == -1:
                        varContent = getVarContent(code, bytes)
                        if len(varContent) > 150:
                            ret = unescape(varContent)
                            if ret[0] != -1:
                                bytes = ret[1]
                                urls = re.findall('https?://.*$', bytes, re.DOTALL)
                                if bytes not in unescapedBytes:
                                   unescapedBytes.append(bytes)
                                for url in urls:
                                   if url not in urlsFound:
                                       urlsFound.append(url)
                    else:
                        bytes = bytes[1:-1]
                        if len(bytes) > 150:
                            ret = unescape(bytes)
                            if ret[0] != -1:
                                bytes = ret[1]
                                urls = re.findall('https?://.*$', bytes, re.DOTALL)
                                if bytes not in unescapedBytes:
                                   unescapedBytes.append(bytes)
                                for url in urls:
                                   if url not in urlsFound:
                                       urlsFound.append(url)
    except:
        traceback.print_exc(file=open(errorsFile, 'a'))
        errors.append('Unexpected error in the JSAnalysis module!!')
    finally:
        for js in jsCode:
            if js is None or js == '':
                 jsCode.remove(js)
    return [jsCode, unescapedBytes, urlsFound, errors, context]


def getVarContent(jsCode, varContent):
    '''
        Given the Javascript code and the content of a variable this method tries to obtain the real value of the variable, cleaning expressions like "a = eval; a(js_code);"
        
        @param jsCode: The Javascript code (string)
        @param varContent: The content of the variable (string)
        @return: A string with real value of the variable
    '''
    clearBytes = ''
    varContent = varContent.replace('\n', '')
    varContent = varContent.replace('\r', '')
    varContent = varContent.replace('\t', '')
    varContent = varContent.replace(' ', '')
    parts = varContent.split('+')
    for part in parts:
        if re.match('["\'].*?["\']', part, re.DOTALL):
            clearBytes += part[1:-1]
        else:
            part = escapeString(part)
            varContent = re.findall(part + '\s*?=\s*?(.*?)[,;]', jsCode, re.DOTALL)
            if varContent:
                clearBytes += getVarContent(jsCode, varContent[0])
    return clearBytes


def isJavascript(content):
    '''
        Given an string this method looks for typical Javscript strings and try to identify if the string contains Javascrit code or not.
        
        @param content: A string
        @return: A boolean, True if it seems to contain Javascript code or False in the other case
    '''
    jsStrings = ['var ', ';', ')', '(', 'function ', '=', '{', '}', 'if(', 'if (', 'else{', 'else {','else if', 'return', 'while(', 'while (', 'for(', 'for (',
                 ',', 'eval']
    keyStrings = [';', '(', ')']
    stringsFound = []
    limit = 15
    #JS should at least contain ';', ')', '(', 'var', '='
    minDistinctStringsFound = 5
    minRatio = 10
    results = 0
    length = len(content)
    smallScriptLength = 100

    if re.findall(reJSscript, content, re.DOTALL | re.IGNORECASE):
        return True
    
    for char in content:
        if (ord(char) < 32 and char not in ['\n', '\r', '\t', '\f', '\x00']) or ord(char) >= 127:
            return False

    for string in jsStrings:
        cont = content.count(string)
        results += cont
        if cont > 0 and string not in stringsFound:
            stringsFound.append(string)
        elif cont == 0 and string in keyStrings:
            return False

    numDistinctStringsFound = len(stringsFound)
    ratio = (results*100.0)/length
    if (results > limit and numDistinctStringsFound >= minDistinctStringsFound) or \
            (length < smallScriptLength and ratio > minRatio):
        return True
    else:
        return False


def searchObfuscatedFunctions(jsCode, function):
    '''
        Search for obfuscated functions in the Javascript code
        
        @param jsCode: The Javascript code (string)
        @param function: The function name to look for (string)
        @return: List with obfuscated functions information [functionName,functionCall,containsReturns] 
    '''
    obfuscatedFunctionsInfo = []
    if jsCode != None:
        match = re.findall('\W('+function+'\s{0,5}?\((.*?)\)\s{0,5}?;)', jsCode, re.DOTALL)
        if match:
           for m in match:
              if re.findall('return', m[1], re.IGNORECASE):
                 obfuscatedFunctionsInfo.append([function, m, True])
              else:
                 obfuscatedFunctionsInfo.append([function, m, False])
        obfuscatedFunctions = re.findall('\s*?((\w*?)\s*?=\s*?'+function+')\s*?;', jsCode, re.DOTALL)
        for obfuscatedFunction in obfuscatedFunctions:
           obfuscatedElement = obfuscatedFunction[1]
           obfuscatedFunctionsInfo += searchObfuscatedFunctions(jsCode, obfuscatedElement)
    return obfuscatedFunctionsInfo


def unescape(escapedBytes, unicode = True):
    '''
        This method unescapes the given string
        
        @param escapedBytes: A string to unescape
        @return: A tuple (status,statusContent), where statusContent is an unescaped string in case status = 0 or an error in case status = -1
    '''
    #TODO: modify to accept a list of escaped strings?
    unescapedBytes = ''
    if unicode:
        unicodePadding = '\x00'
    else:
        unicodePadding = ''
    try:
        if escapedBytes.lower().find('%u') != -1 or escapedBytes.lower().find('\u') != -1 or escapedBytes.find('%') != -1:
            if escapedBytes.lower().find('\u') != -1:
                splitBytes = escapedBytes.split('\\')
            else:
                splitBytes = escapedBytes.split('%')
            for i in range(len(splitBytes)):
                splitByte = splitBytes[i]
                if splitByte == '':
                    continue
                if len(splitByte) > 4 and re.match('u[0-9a-f]{4}', splitByte[:5], re.IGNORECASE):
                    unescapedBytes += chr(int(splitByte[3]+splitByte[4], 16))+chr(int(splitByte[1]+splitByte[2],16))
                    if len(splitByte) > 5:
                        for j in range(5,len(splitByte)): 
                            unescapedBytes += splitByte[j] + unicodePadding
                elif len(splitByte) > 1 and re.match('[0-9a-f]{2}', splitByte[:2], re.IGNORECASE):
                    unescapedBytes += chr(int(splitByte[0]+splitByte[1], 16)) + unicodePadding
                    if len(splitByte) > 2:
                        for j in range(2,len(splitByte)): 
                            unescapedBytes += splitByte[j] + unicodePadding
                else:
                    if i != 0:
                        unescapedBytes += '%' + unicodePadding
                    for j in range(len(splitByte)):
                        unescapedBytes += splitByte[j] + unicodePadding
        else:
            unescapedBytes = escapedBytes
    except:
        return (-1, 'Error while unescaping the bytes')
    return (0, unescapedBytes)


if __name__=='__main__':
    s1="""2 J
    0.57 w
    BT /F1 12.00 Tf ET
    BT 31.19 802.04 Td (Fixedly i there up the rinieri . Portals close texture of acheron winds wherewith. Meets the bounds such gone from death from troy when. Addressed me sufficient, ere thou. Inhabitants with woe? then . Heartstruck i soon that blasphemies gainst each here? he himself, and stands. Seems, heeds not ever after many reproof before me scatterd leaves. Sweet, that forces out that part in headlong fell spirits, who thundring. Haply thoughtst me uninterrupted traverses the rough. Arguments, of showrs ceaseless, accursed, heavy, and which. Extremity arriving of authority permitted . Denying and note of themselves the loins so wake. Fate suffer not but while. Main-sail rent throughout; and showing us of justice lays chastising hand . Horn? your skirmishing secure, my judgment to west, a . Courseth down to great city i come note. At sight and what dost hope there. Grapple that, us? to shake off a sinners pine phlegyas. Arno, that trophy crownd penelope with earth puts on droppd the hideous. Hither: once pondring now passd on not beware. Spirit movd ever hath passd, still walld in pen wrote o . Comes one builds anew, another stops the lists of tyrants, who field. Dream, and court of himself distance from hoarse with words, whose eyes. Aghast the caldron down its sweeter hymns became that triumph. Knowest shouts his device, mischievous . Age were separate from renownd, learnd to nessus yet to assaild . Guard the height all wants, and though unweeting that. Encrusting hung, and be weary of sublimest song, whose sake. Prato, not mound, reard once with thee . Caitiff? on rank; democritus, who fears not leave thee. Frenchmans gold and bate their unkindly visage saves from. Taught, betwixt the rocks low melancholy sounds, made from clothd me wholly. Retrace the tyrannous gust those fewer who clear! he, rout oerthrew. Forespent, we unopposd there no little it shall strange, through its departure. Naso; lucan in neighbours are two shorter feet. Saracens or layman known . Dropsy, disproportioning the ended . Mutual war there cocytus, of host. Covertly, but fraud, because they at some compensation find. Device, mischievous as a felon deeds shew thee. Presageful, thou he brings thee stay and styx, and baptists form distorted. What, and now wax, each extremity arriving . Vexd with such now bethink. Tempers his train divided to briefly ye spirits: arrivd below were their. Back the foots sinew griping. Zeal have quelld the almighty foe to best, the drenchd in scum. Sand, its language turnd back his filth disguisd sacristy. Gurgle in tears droppd to human. Surface, scarcely firm embattled spears, and cahors. Arno, that serchios wave yet thou. Stripe! none are turnd . Rest? he hunt approach or else so therefore: but follow me . Shades, on bethought him draghinazzo haste. Next, whose heads are last a scurf from. Jason is castles were we, a thick beset. Wound, the satan! loud moans resounded through these florentines . Strove, so foul? one, impatient to descend into nearer. Drops hither, ere a soul . Seem fire-illumd are one belly . Sevral moons had but back; for plastic hand might . Along; thus fourth time of heavn dawnd through latter . Litanies on our eyes from. Cumber earth who sped lucia, of intellect sound and boding . Stain imbrud; if he, whom soon friend the plumes, that most unholy. Inventions multiform, our seeking him be pleasd. Whole must below were only. Him: capaneus! thou must needs . Toils releasd all bar his labours with silent. Ford may see or of pity most doth. Thyself if sings my dismay renews, in sounded aloud their pangs hardily. First behoves make the ten let similar, so obsequious. Shoulder joind the nails serve . Bit, and back; for water-fowl when. Visages of and, if virtue to bred and thickets close. Pack, who under close in tears ever close . Catch its mould, did space of ample. Waited nor movd to our sad reversd, and muttring thunder feeble grasping. Leprous spirit in whom hector . Rebukd him bespake: pause, and feet were. Envious, proud scorn, but she in corruptible flesh, among languishes . Acre one have their ear lopt off, who dwell not . Concealed, thus reachd; but mincius, till . Breath of brake to all . Exhald its base, as hangs the stoutest. Towerd at journey bent; for this. Gnats, or foam upon marvel where chin, the frogs, that doth. Cares not removd farthest from. Curb the power to wail, borsiere, yonder walking with shadows. Alone; so words; at judgment. Sand: look to devil black, and empedocles. Fruit i thread and names that mounted on earth; and sustain. Fable, where will instruct me, soon both what this. Muddy lees; nor spread wings and tegghiaio say, did seat . Uprearing, horrible, whom i not rack thy wishes it seems to kennd. Air, that ere vain . Mass had sustaind, whereat i prime, and tournaments, and matted thick. Justice, dooms it to many stain-- to her plastic hand. You one, impatient eagerness of way broke. Wherein thy crimes?--him death oertook him thou fresh and their. Pains rack thy eloquent persuasive tongue. Poet gaind, when him . Wrench her walls with bloody foam upon strode. Change th together short course. Sith he made mangled, then waggd the point. Lucia calling, her way aloft he said. Quitting us, if on eternal then had exempted, he whose canopy reposing. ) Tj ET"""

    isJavascript(s1)