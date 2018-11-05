var zzzactivex = [];
function Plugin(name,fname,desc){
    this.name = name;
    this.filename = fname;
    this.description = desc;
}
var PluginArray = function _PluginArray(){ 
    this.toString = function(){
        return '';
    };

};
PluginArray.prototype = new Array;
var my_plugins = new PluginArray();
my_plugins.push(new Plugin('getPlusPlus for Adobe 16263','np_gp.dll','getplusplusadobe16263'));
my_plugins.push(new Plugin('Google Talk Plugin','npgoogletalk.dll','Version 1,0,21,0'));
my_plugins.push(new Plugin('Adobe Acrobat','nppdf32.dll','Adobe PDF Plug-In For Firefox and Netscape'));
my_plugins.push(new Plugin('Mozilla Default Plug-in','npnul32.dll','Default Plug-in'));
my_plugins.push(new Plugin('Microsoft Office 2003','NPOFFICE.DLL','Office Plugin for Netscape Navigator'));
my_plugins.push(new Plugin('Google Update','npGoogleOneClick8.dll','Google Update'));
my_plugins.push(new Plugin('Shockwave Flash','NPSWF32.dll','Shockwave Flash 10.0 r32'));
my_plugins.push(new Plugin('Silverlight Plug-In','npctrl.dll','3.0.50106.0'));
my_plugins.push(new Plugin('Microsoft Office Live Plug-in for Firefox','npOLW.dll','Office Live Update v1.4'));
my_plugins.push(new Plugin('Windows Live® Photo Gallery','NPWLPG.dll','NPWLPG'));
my_plugins.push(new Plugin('Java Deployment Toolkit 6.0.140.8','npdeploytk.dll','NPRuntime Script Plug-in Library for Java(TM) Deploy'));
my_plugins.push(new Plugin('Java(TM) Platform SE 6 U14','npjp2.dll','Next Generation Java Plug-in 1.6.0_14 for Mozilla browsers'));

function my_navigator(){
	this.appCodeName = String("Mozilla");
	this.appMinorVersion = String(";SP2;");
	this.appName = String("Microsoft Internet Explorer");
	this.appVersion = String("4.0 (compatible; MSIE 7.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322; .NET CLR 2.0.50727)");
	this.browserLanguage = String("en");
	this.cookieEnabled = String("true");
	this.cpuClass = String("x86");
	this.onLine = String("true");
	this.platform = String("Win32");
	this.systemLanguage = String("en");
	this.userAgent = String("Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322; .NET CLR 2.0.50727)");
	this.userLanguage = String("en ");
	this.javaEnabled = function(){ return true; }
    this.taintEnabled = function(){ return 0; }
    this.mimeTypes = {};
    this.plugins = my_plugins;
}
var navigator= new my_navigator();
var screen = {};

var app = {
	viewerVersion:Number(8.0),
    viewerType:String('Reader'),
	setTimeOut:function(txt,wait){ eval(txt); print ("; //jsunpack.called setTimeOut with "+txt + ', ' + wait);},
	clearTimeOut:function(a){},
	eval:function(a){eval(a);},
    alert:function(a){ print ("/*** app.alert " + a + "*/"); },
};

function my_activex(){
    zzzactivex.push(this);
	this.donePath = 0;
	this.SaveToFile = this.savetofile = function (txt){ print("//jsunpack.save " + txt) }
	this.close = function(){ }
	this.ChatRoom = function (txt){ print("//alert CVE-2007-5722 ChatRoom len(" + txt+ ")") }
	this.LinkSBIcons = function (txt) { print("//alert CVE-2006-5820 LinkSBIcons len("+ txt.length + ")"); }
	this.Write = this.write = function (txt){ print("//jsunpack.write " + txt) }
	this.Send = this.send = function (){}
    this.OpenWebFile = function(url){
        print("//jsunpack.url OpenWebFile = " + url)
    }
	this.Open = this.open = function (method,url,t_f){ 
		if (arguments.length >= 2){
			//var method = arguments[0];
			var url = arguments[1];
			//var t_or_f = arguments[2];
			print("//jsunpack.url open = " + url) 
		}
	}
	this.shellexecute = this.ShellExecute = function(cmd){ print("//alert CVE-2006-0003 shellexecute with " + cmd); }
	this.BuildPath = this.buildpath = function(a,b){ this.donePath = 1; }
	this.CompressedPath = this.compressedpath = function(a,b){ this.donePath = 1; }
	this.PrintSnapshot = function (){
		if (arguments.length >= 2){
			file = arguments[0];
			dest = arguments[1];
			print("//jsunpack.url PrintSnapshot = " + file);
		}
		if(this.SnapshotPath || this.CompressedPath || this.donePath){
			print("//alert CVE-2008-2463 PrintSnapshot");
		}
		else {
			print("//jsunpack.called PrintSnapshot") 
		}
	}
	this.GetSpecialFolder = this.getspecialfolder = function (a){ /*print("//alert CVE-2006-0003 GetSpecialFolder");*/ }
	this.hgs_startNotify = function (tmp){ print("//alert CVE-2008-0647 hgs_startNotify len("+tmp.length+")") }
	this.TransferFile = this.transferfile = function (url,host,local,sploit,md5){ print("//alert CVE-2008-1724 Tumbleweed FileTransferActiveX len(" + sploit.length + ")"); }
	this.setRequestHeader = function (a,b){ if(typeof a == 'object'){ print ("//alert CVE-2006-5745 MSXMLCoreServices setRequestHeader with [Object]"); } }
	this.getIcon = function (i){ print("//alert CVE-20090927 getIcon len("+i.length+")") }
	this.SetFormatLikeSample = function (a){ print("//alert CVE-2007-0018 SetFormatLikeSample len(" + a.length + ")\n") }
	this.PlayerProperty = function (s){ return "6.0.14.544"; }
	this.import = function (a,b,c,d,e){ print("//alert CVE-2007-5601 import playlist length=" + b.length); }
	this.msDataSourceObject = function(a){ print("//alert CVE-2009-1136 msDataSourceObject"); }
}
var the_activex = new my_activex();

function my_element(){
    this.setAttribute=function (name,value){
	if(name=='src'){
		print("//jsunpack.url setAttribute src = " + value);
	}
    }	
    this.CreateObject=function (){
	var name = '';
	var other = '';
	
	if (arguments.length >= 1){
		name = arguments[0];
	}
	if (arguments.length >= 2){
		for (var i = 1; i < arguments.length; i++){
			other = other + arguments[i];
		}
	}

	text = "//jsunpack.CreateObject " + name + " " + other;
	if(exploits.indexOf(text) == -1){
		print (text);
		exploits.push(text);
	}
	return new my_activex();
    }
    this.createobject = this.CreateObject;
    this.appendChild=function (obj1){
        //This is an object, may be more interesting if we extract attributes
        if ('text' in obj1){
            print ('//appendChild text');
            print (obj1.text);
        }
    }
}
var exploits = [];
var namezzz = {}; //for getElementByTagName

//For getElementById , innerHTML
var idzzz = []; var valzzz = []; var txtzzz = [];
//For activex array


function my_style(){
    this.display = 'none';
}
style = new my_style();

function my_value(i){
    this.value = valzzz[i];
    this.innerText = txtzzz[i];
    this.innerHTML = txtzzz[i];
    this.style = style;
    this.object = new my_activex();
    this.onclick = function(){};
    this.appendChild = function(obj1){
        try{
            if (obj1.src){
                print ('//jsunpack.url var appendChildsrc = ' + obj1.src);
            }
        }
        catch(e){}
    };
}
var elements = [];
var elementn = -1;
var documenttxt = String('');
var document= 	{ 
		writeln : function(){
			var thisWrite = String();
			for (var i = 0; i < arguments.length; i++){
				thisWrite = thisWrite + escape(arguments[i] + '\n');
			}
			documenttxt = documenttxt + unescape(thisWrite.replace(/%00/g,''));
		},
		write : function(){
			var thisWrite = String();
			for (var i = 0; i < arguments.length; i++){
				thisWrite = thisWrite + escape(arguments[i]);
			}
			documenttxt = documenttxt + unescape(thisWrite.replace(/%00/g,''));
		},

		createElement : function(ele){print ('//jsunpack.called CreateElement ' +ele); elementn = elementn + 1; elements[elementn] = new my_element(); return elements[elementn]},
		getElementById : function(i){ return new my_value(idzzz.indexOf(i)); },
		getElementsByTagName : function(name){ if (name in namezzz){return namezzz[name];} return []; },
		createEventObject : function(evt){ /* object returned has srcElement property */},
		};
document.title = String('My Title');
document.location = String('http://localhost/');
document.body = new my_element();
document.cookie = String();
document.documentElement = new Array();

var remainingActiveXobjects = 100;
function ActiveXObject(text){
	if(remainingActiveXobjects > 0){
		remainingActiveXobjects = remainingActiveXobjects -1;
		text = '\n//info.ActiveXObject '+text+'\n';
		if(exploits.indexOf(text) == -1){
			print(text);
			exploits.push(text);
		}
		
		return new my_activex();
	}
	return null;
}
this.frames = new Array();
this.frames.self=this;
this.self = this;

var window = this;
window.unescape = unescape;
window.parent = window;
window.execScript = eval;
window.eval = eval;
window.Option = 1;
window.open = function (url){
    print("//jsunpack.url open = " + url) 
};

String.eval = eval;
this.addEventListener = function (action, func, torf){
	eval(func);
}
this.attachEvent = function (action, func){
	eval(func);
}

var parent = window;
var parentWindow = window;
document.parentWindow = parentWindow;
var self = this;
self.self = this;

//If you don't plan to modify and compile spidermonkey, enable this!
var my_eval = this.eval;
this.eval=function (str){
	print('\n//eval\n'+str);
	return my_eval(str);
}

this.setTimeout=function(fn,time){
	eval(fn);
	print("/*** called setTimeout with " + fn + ", " + time + " */\n");
}

var app;
var intervalExec = '';
app.setInterval = function(fn,time){
	if (time > 500){
		//delay until the end of execution
		intervalExec += fn;
		print("/*** called setInterval with " + fn + ", " + time + " (delaying) */\n");
	}
	else {
		eval(fn);
		print("/*** called setInterval with " + fn + ", " + time + " */\n");
	}
}
this.setInterval = app.setInterval;

var info = { title : '' };
var media = {
	newPlayer : function(a){ 
		if (a == null){ 
			print("//alert CVE-2009-4324 media.newPlayer with NULL parameter"); 
		} 
		else { 
			print("//warning CVE-2009-4324 media.newPlayer access"); 
		} 
	},
	createPlayer : function(a){
		print("//warning CVE-2009-4324 media.newPlayer access");
	},
};
var zzzannot = [];
var zzzannot2 = {};
app.doc = {
	syncAnnotScan : function(){},
    getAnnot : function(pageNo,name){
        if (name in zzzannot2){
            return zzzannot2[name];
        }
        if (zzzannot.length > pageNo){
           return zzzannot[pageNo][0]; 
        }
    },
	getAnnots : function(){ 
		for (var i = 0; i < arguments.length; i++){
            npage = -1;
            if (typeof arguments[i] == 'number'){
                npage = arguments[i];
            }
            else if ('nPage' in arguments[i]){
                npage = arguments[i].nPage;
            }
            if (npage > -1){
				if (zzzannot.length > npage){
					return zzzannot[npage];
				}
			}
		}
        if (arguments.length == 0){
            if (zzzannot.length > 0){
                return zzzannot[0];
            }
        }
	},
    Function : function(thefunc){
        print (thefunc);
    },
    printSeps : function(){
        print ("//alert CVE-2010-4091 doc.printSeps access");
    },
};

function my_collab(){
	this.collectEmailInfo = function (txt){ print ("//jsunpack.called Collab.collectEmailInfo"); }
	this.getIcon = function (i){ print("//jsunpack.called collab.getIcon ") }
}
var Collab = new my_collab();
var getAnnot = app.doc.getAnnot;
var getAnnots = app.doc.getAnnots;
var syncAnnotScan = app.doc.syncAnnotScan;
app.doc.Collab = Collab;
app.doc.media = this.media;
app.media = this.media;
var doc = app.doc;
var printSeps = app.doc.printSeps;
this.exportDataObject = function(){
    print ("//warning CVE-NO-MATCH call to exportDataObject, possible social engineering");
};
function PlugIn(name,filename){
    this.name = name;
    this.path = "/C/Program Files/Adobe Reader 8.0/Reader/plug_ins/" + filename;
    this.version = 8;
    this.certified = false;
    this.loaded = true;
    this.toString = function(){ return this.path; }
    this.valueOf = function(){ return this.path; }
}
app.plugIns = [];
app.plugIns.push(new PlugIn('Accessibility','Accessibility.api'));
app.plugIns.push(new PlugIn('Forms','AcroForm.api'));
app.plugIns.push(new PlugIn('Annots','Annots.api'));
app.plugIns.push(new PlugIn('Checkers','Checkers.api'));
app.plugIns.push(new PlugIn('DIGSIG','DigSig.api'));
app.plugIns.push(new PlugIn('ADBE:DictionaryValidationAgent','DVA.api'));
app.plugIns.push(new PlugIn('eBook','eBook.api'));
app.plugIns.push(new PlugIn('EScript','EScript.api'));
app.plugIns.push(new PlugIn('EWH','EWH32.api'));
app.plugIns.push(new PlugIn('AcroHLS','HLS.api'));
app.plugIns.push(new PlugIn('InetAxes','IA32.api'));
app.plugIns.push(new PlugIn('SVG','ImageViewer.api'));
app.plugIns.push(new PlugIn('Make Accessible','MakeAccessible.api'));
app.plugIns.push(new PlugIn('Multimedia','Multimedia.api'));
app.plugIns.push(new PlugIn('PDDom','PDDom.api'));
app.plugIns.push(new PlugIn('ppklite','PPKLite.api'));
app.plugIns.push(new PlugIn('ReadOutLoud','ReadOutLoad.api'));
app.plugIns.push(new PlugIn('Reflow','reflow.api'));
app.plugIns.push(new PlugIn('SaveAsRTF','SaveAsRTF.api'));
app.plugIns.push(new PlugIn('ADBE_Search','Search.api'));
app.plugIns.push(new PlugIn('ADBE_Search5','Search5.api'));
app.plugIns.push(new PlugIn('SendMail','SendMail.api'));
app.plugIns.push(new PlugIn('Spelling','Spelling.api'));
app.plugIns.push(new PlugIn('Updater','Updater.api'));
app.plugIns.push(new PlugIn('WebLink','weblink.api'));
var util = {
	printf : function(a,b){print ("//alert CVE-2008-2992 util.printf length ("+ a.length + "," + b.length + ")\n"); },
	printd : function(){ print("//warning CVE-2009-4324 printd access"); },
};
var zzzpages = [];
this.numPages = 0;
this.pageNum = 0;
var getPageNthWord = function(page,word) { return zzzpages[page][word]; }
var getPageNumWords = function(page) { print ("//info getPageNumWords("+page+")"); return zzzpages[page].length; }

//Static Functions - common but useless
function CollectGarbage(){}
function urchinTracker(){}
function my_location(one,two){ 
	this.href = String(one); 
	this.host = String(two); 
    this.assign = function (newurl){
        print ('//jsunpack.url locationAssign = ' + newurl);
    };
    document.location = this;
    window.location = this;
    windowlocation = this;
    location.pathname = String(this.href);

} 
function attachEvent(action, fun) {
	//print ('attachevent');
}
var location = new my_location('http://example.com','example.com'); 
document.location = location; 
window.location = location; 
var windowlocation = location;
var documentlocation = document.location;
var control = {
	getVersions: function(){ return 0; }
};
var event = {};
event.target = this;
var alert = function(){}
window.alert = alert;
var prompt = function(){ return 1; }
window.prompt = prompt;
var confirm = function(){ return 1; }
window.confirm = confirm;
window.top = window;
window.self = window;
window.window = window;
var Run = function(arg){
    print("//warning CVE-2010-1885 possible hcp URL with Run access"); 
    print ('/* Run arguments:');
    print (arg);
    print ('*/');
};
var string = String;
var console = new Object();
console.println = function(arg){ print ("/* console.println " + arg + "*/"); }
