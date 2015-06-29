/***
Yara Rules file for jsunpackn 
http://jsunpack.jeek.org/
Blake Hartstein 
blake[@]jeek.org
Feel free to send me new or custom rules!
If you want the most up to date rules, check http://jsunpack.jeek.org/dec/current_rules

Last updated 3/22/2010

Alert modifiers: (does not affect detection)
	ref = CVE-NAME
	impact = (between 0 - 10, 10 being most severe)
	hide = (true|false), if hide=true, don't pass detected strings to program
		use this if the rule name captures everything of value, or you just don't care about the data
	

Detection modifiers:
	decodedPDF = rules that only alert if decoding within a PDF file
	decodedOnly = rules that only alert if decoding level > 0 (ie. a decoding and not the original file)

	(add your own) I will support them (maybe not) ;)
*/

rule Utilprintf: decodedPDF
{
	meta:
		ref = "CVE-2008-2992"
		hide = true
	strings:
		$cve20082992 = "util.printf" nocase fullword
	condition:
		1 of them
}
rule SpellcustomDictionaryOpen: decodedPDF
{
	meta:
		ref = "CVE-2009-1493"
		hide = true
	strings:	
		$cve20091493 = "spell.customDictionaryOpen" nocase fullword
	condition:
		1 of them
}
rule printSeps: decodedPDF
{
    meta:
        ref = "CVE-2010-4091"
        hide = true
    strings:
        $cve20104091_1 = "doc.printSeps"
        $cve20104091_2 = "this.printSeps"
    condition:
        1 of them
}
/* 

//This rule is not strong enough, handled by detecting createElement x 100 in pre.js now
rule MSIEUseAfterFree: decodedOnly
{
	meta:
		ref = "CVE-2010-0249"
		hide = true
        impact = 5
	strings:
		$cve20100249_1 = "createEventObject" nocase fullword
		$cve20100249_2 = "getElementById" nocase fullword
		$cve20100249_3 = "onload" nocase fullword
		$cve20100249_4 = "srcElement" nocase fullword
	condition:
		all of them
}
*/
rule getAnnots: decodedPDF
{
	meta:
		impact = 3  //Since getAnnots may be legitimate
        ref = "CVE-2009-1492"
		hide = true
	strings:
		$cve20091492 = "getAnnots" nocase fullword
	condition:
		1 of them
}
rule mediaNewplayer: decodedPDF
{
	meta:
		ref = "CVE-2009-4324"
		hide = true
	strings:
		$cve20094324 = "media.newPlayer" nocase fullword
	condition:
		1 of them
}
rule collectEmailInfo: decodedPDF
{
	meta:
		ref = "CVE-2007-5659"
		hide = true
	strings:
		$cve20075659 = "collab.collectEmailInfo" nocase fullword
	condition:
		1 of them
}
rule CollabgetIcon: decodedPDF
{
	meta:
		ref = "CVE-2009-0927"
		hide = true
	strings:		
		$cve20090927 = "collab.getIcon" nocase fullword
	condition: 
		1 of them
}
rule PDFobfuscation: decodedPDF
{
	meta:
		impact = 5
	strings:	
		$cveNOMATCH  = "collab[" nocase 		//hidden collab string
	condition: 
		1 of them
}
rule UnconfirmedPDFexploit: decodedPDF
{ 	
	meta:
		impact = 0
		//unconfirmed exploitation
	strings:
		$cve20084813 = "getCosObj" nocase fullword
		$cve20082042 = "app.checkForUpdate" nocase fullword
		$cve20080726 = "printSepsWithParams" nocase fullword
		$cve20073902 = "setExpression" nocase fullword
		$cve20090773 = "ResizeSlots" nocase fullword
	condition:
		1 of them
}
rule DecodedGenericCLSID : decodedOnly
{
	meta:
		impact = 0
	strings:
		$gen = /[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/ nocase
	condition:
		1 of them
}
rule MSOfficeSnapshotViewer
{
	meta:
		ref = "CVE-2008-2463"
		impact = 7
	strings:
		$cve20082463 = /(F0E42D50|F0E42D60|F2175210)-368C-11D0-AD81-00A0C90DC8D9/ nocase
	condition:
		1 of them
}
rule MSOfficeWebComponents
{	//Expect ActiveX with it, OWC10.Spreadsheet OWC11.Spreadsheet
	meta:
		ref = "CVE-2009-1136"
		impact = 7
	strings:
		$cve20091136_1 = "msDataSourceObject" nocase fullword
		$cve20091136_2 = "OWC10.Spreadsheet" nocase fullword
		$cve20091136_3 = "OWC11.Spreadsheet" nocase fullword
	condition:
		1 of them
}
rule COMObjectInstantiationMemoryCorruption
{
	meta:
		ref = "CVE-2005-2127"
		impact = 7
	strings:
		$cve20052127 = "EC444CB6-3E7E-4865-B1C3-0DE72EF39B3F" nocase fullword
	condition:
		1 of them
}
/** rule MSXMLCoreServicesdd
{ //match with open(a,b,c,d,e)? or setRequestHeader?
	meta:
		ref = "CVE-2006-5745"
		impact = 7
	strings:
		$cve20065745 = "88d969c5-f192-11d4-a65f-0040963251e5" nocase fullword
	condition:
		1 of them
}*/
rule MSDirectShowCLSID
{
	meta:
		ref = "CVE-2008-0015"
		impact = 7
	strings:
		$cve20080015 = "0955AC62-BF2E-4CBA-A2B9-A63F772D46CF" nocase fullword
	condition:
		1 of them
}
rule MSWindowsVMLElement
{
	meta:
		ref = "CVE-2007-0024"
		impact = 7
	strings:
		$cve20070024 = "10072CEC-8CC1-11D1-986E-00A0C955B42E"
	condition:
		1 of them
}
rule MSsetSlice
{
	meta:
		ref = "CVE-2006-3730"
		impact = 4
	strings:
		$cve20063730_1 = "setSlice" nocase fullword
		$cve20063730_2 = "WebViewFolderIcon.WebViewFolderIcon.1" nocase fullword
	condition:
		1 of them
}
rule ActiveXDataObjectsMDAC
{
	meta:
		impact = 0
	strings:
		$cve20060003_1 = "MSXML2.ServerXMLHTTP" nocase fullword
		$cve20060003_2 = "Microsoft.XMLHTTP" nocase fullword
	condition:
		1 of them		
}
rule AOLSuperBuddyActiveX
{
	meta:
		ref = "CVE-2006-5820"
		impact = 7
	strings:
		$cve20065820 = "Sb.SuperBuddy.1" nocase fullword
	condition:
		1 of them
}
rule Alert
{
	strings:
		$alert = /\/\/alert CVE-.+/
	condition:
		1 of them
}
rule Warning
{
	meta:
		impact = 5
	strings:
		$alert = /\/\/warning CVE-.+/
	condition:
		1 of them
}
rule DecodedMsg
{
	meta:
		impact = 0
	strings:
		$activex = /\/\/info\.ActiveXObject (.*)/
		$shellcode = /\/\/shellcode len .{150,}/	//150 is %u1234 (6 characters) X (25)
		//jsunpack\..*
	condition:
		1 of them
}
rule DecodedIframe: decodedOnly 
{
	meta:
		impact = 0
		hide = true
	strings:
		$iframe = "<iframe" nocase fullword

		//possible in the future, if alerts are too common:
		//style\s*=["'\s\\]*([a-z0-9:\s]+;\s*)?(display\s*:\s*none|visibility\s*:\s*hidden)
		//(width|height)\s*=["'\s\\]*[01]["'\s\\>]
		//style=['"]display:none['"]>\s*<iframe 
		//src\s*=\s*['"\s\\]*(&#\d+){10}
		
		//advertisers use DecodedIframe all the time
		//maybe domain name whitelisting? 
	condition:
		1 of them
}
/*
rule ObfuscationPattern
{ 
	meta:
		impact = 0
	strings:
		$eval = "eval" nocase fullword
		$charcode = "String.fromCharCode" nocase fullword
		$loc = "location" nocase fullword
		$deanEdwards = "function(p,a,c,k,e,d)" nocase
	condition:
		2 of them
}*/
rule SuspicousBodyOnload
{
	meta:
		impact = 6
		hide = true
	strings:
		$body = /<body [^>]*onload\s*=\s*['"]*[a-z0-9]+\(['"][a-f0-9]{300}/
	condition:
		1 of them
}
rule MSIENestedSpan
{
	meta:
		ref = "CVE-2008-4844"
		impact = 8
		hide = true
	strings:
		$cve20084844_1 = "<span datasrc=" nocase
		$cve20084844_2 = "CDATA[<image SRC=http://&#" nocase
		$cve20084844_3 = "dataformatas=" nocase
		$cve20084844_4 = "datasrc=" nocase
		$cve20084844_5 = "datafld=" nocase
	condition:
		all of them
}
/*
rule ShellcodePattern
{
    meta:
        impact = 1 //while testing
        hide = true
    strings:
        $unescape = "unescape" fullword nocase
        $shellcode = /%u[A-Fa-f0-9]{4}/ 
        $shellcode5 = /(%u[A-Fa-f0-9]{4}){5}/
    condition:
        ($unescape and $shellcode) or $shellcode5
}
*/
rule MSIEUseAfterFreePeersDll
{
    meta:
        ref = "CVE-2010-0806"
        hide = true
        impact = 5
    strings:
        $cve20100806_1 = "createElement" nocase fullword
        $cve20100806_2 = "onclick" nocase fullword
        $cve20100806_3 = "setAttribute" nocase fullword
        $cve20100806_4 = "window.status" nocase fullword
        $cve20100806_5 = /getElementById[^<>;]+\.onclick/ nocase
    condition:
        all of them
}

