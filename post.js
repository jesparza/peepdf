// post processing, run this file after the main js file is interpreted.
// print out results
//document.myd_data();

if (window.onload){
	window.onload();
}

if (intervalExec){
	eval(intervalExec);
}
if ( elementn > 100){
    print ('\n//alert CVE-2010-0249 MSIEUseAfterFree (CreateElement called ' + elementn + ' times)');
}
if ( elementn > -1 ){
	for (var i = 0; i <= elementn; i++){
		print ('\n//jsunpack.url '+ elements[i].src);
	}
}
if ( windowlocation != window.location){
	print ("\n//jsunpack.location '" + window.location + "' where windowlocation = '" + windowlocation + "'");
}
if(documenttxt){
	print ('\n//document.write (s)\n');
	print (documenttxt);
}
//finalvars = [];
//finalcount = 0;
for (var i in this){
	var objlen = 0;
	if (typeof this[i] == 'object'){
		tmp = String(this[i]); //this[i] = String(this[i]);
		objlen = tmp.length;
		if (objlen > 10000){ //Memory/performance intensive beyond this
			this[i] = tmp.substring(0,10000);
		}
	}
    if (typeof this[i] == 'string' && i != 'documenttxt' && i != 'i' && i != 'txtzzz'){
        //if (escape(this[i]).match(/^(%u.{4})+(%..)*$/)){ //STRICT SHELLCODE DETECTION (disabled by default)
        if (escape(this[i]).match(/%u/)){ //LOOSE SHELLCODE DETECTION (enabled by default)
            var prelen = this[i].length;
            if (prelen > 100){
                this[i] = this[i].replace(/(.)\1{10}/g,'');
                //NOPs
            }
            var postlen = this[i].length;

            if (prelen - postlen > 100){
                print ('//warning CVE-NO-MATCH Shellcode NOP len ' + (prelen - postlen));
            }
            if (objlen > prelen){
                prelen = objlen;
            }
            print ('//shellcode len ' + prelen + ' (including any NOPs) ' + i + ' = ' + escape(this[i]));
        }
        else if (this[i].match(/http:/)){
            var newurl = this[i];
            if (newurl.length > 255){
                newurl = newurl.substring(0,255);
            }
            print ('//jsunpack.url var ' + i + ' = ' + newurl + '\n');
        }
        else if (this[i].match(/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/i)){
            print ('//info.ActiveXObject '+this[i]+'\n');
        }
        //else {
            //[DEBUG] VERY noisy
            //print (i + ' = ' + this[i]);
        //}

        /*if (this[i].toSource().length < 100000){
            finalvars[finalcount] = '//jsunpack.var ' + i; //' = ' + this[i].toSource();
            finalcount++;
        }*/

			
    }
}
/*print ('//jsunpack.final variable enumeration');
for (var f in finalvars){
	print (finalvars[f]);
}*/
