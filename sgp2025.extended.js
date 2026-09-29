javascript:(function(){
  /*
   * MIT License
   * Copyright (c) 2025 Vladimir Kozhevin
   *
   * Permission is hereby granted, free of charge, to any person obtaining a copy
   * of this software and associated documentation files (the "Software"), to deal
   * in the Software without restriction, including without limitation the rights
   * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   * copies of the Software, and to permit persons to whom the Software is
   * furnished to do so, subject to the following conditions:
   *
   * The above copyright notice and this permission notice shall be included in
   * all copies or substantial portions of the Software.
   *
   * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
   * THE SOFTWARE.
   */
  // Extended, readable version of sgp2025.js
  // Notes on short-name mapping from compact version:
  // - rl -> rotateLeft, au -> addUnsigned
  // - FF/GG/HH/II -> md5 round functions
  // - c -> convertStringToWordArray (MD5 padding)
  // - w -> wordToHex
  // - hx -> hexToBytes, b64 -> base64Encode, cb -> customBase64
  // - hm -> hashMd5Base64
  // - e -> extractHostname, rs -> removeSubdomains
  // - v -> validatePasswordPolicy, gp -> generatePassword, ui -> createUI

  function rotateLeft(value, shiftBits){
    return (value << shiftBits) | (value >>> (32 - shiftBits));
  }
  function addUnsigned(x, y){
    var x4 = (x & 0x40000000), y4 = (y & 0x40000000);
    var x8 = (x & 0x80000000), y8 = (y & 0x80000000);
    var result = (x & 0x3FFFFFFF) + (y & 0x3FFFFFFF);
    if (x4 & y4) return (result ^ 0x80000000 ^ x8 ^ y8);
    if (x4 | y4) return (result & 0x40000000) ? (result ^ 0xC0000000 ^ x8 ^ y8) : (result ^ 0x40000000 ^ x8 ^ y8);
    return (result ^ x8 ^ y8);
  }
  function F(x,y,z){ return (x & y) | ((~x) & z); }
  function G(x,y,z){ return (x & z) | (y & (~z)); }
  function H(x,y,z){ return (x ^ y ^ z); }
  function I(x,y,z){ return (y ^ (x | (~z))); }
  function FF(a,b,c,d,x,s,ac){ a = addUnsigned(a, addUnsigned(addUnsigned(F(b,c,d), x), ac)); return addUnsigned(rotateLeft(a,s), b); }
  function GG(a,b,c,d,x,s,ac){ a = addUnsigned(a, addUnsigned(addUnsigned(G(b,c,d), x), ac)); return addUnsigned(rotateLeft(a,s), b); }
  function HH(a,b,c,d,x,s,ac){ a = addUnsigned(a, addUnsigned(addUnsigned(H(b,c,d), x), ac)); return addUnsigned(rotateLeft(a,s), b); }
  function II(a,b,c,d,x,s,ac){ a = addUnsigned(a, addUnsigned(addUnsigned(I(b,c,d), x), ac)); return addUnsigned(rotateLeft(a,s), b); }

  // convertStringToWordArray (short: c)
  function convertStringToWordArray(input){
    var l = input.length;
    var paddedPlus8 = l + 8;                // compact: pa
    var blocks = Math.floor(paddedPlus8 / 64); // compact: pb
    var totalWords = (blocks + 1) * 16;     // compact: n
    var wordArray = new Array(totalWords);  // compact: ar
    for (var i = 0; i < totalWords; i++) wordArray[i] = 0;

    var byteCount = 0;                      // compact: ct
    var bytePos = 0;                        // compact: p
    var wordIndex = 0;                      // compact: w
    while (byteCount < l){
      wordIndex = (byteCount - (byteCount % 4)) / 4;
      bytePos = (byteCount % 4) * 8;
      wordArray[wordIndex] = wordArray[wordIndex] | (input.charCodeAt(byteCount) << bytePos);
      byteCount++;
    }
    wordIndex = (byteCount - (byteCount % 4)) / 4;
    bytePos = (byteCount % 4) * 8;
    wordArray[wordIndex] = wordArray[wordIndex] | (0x80 << bytePos);
    wordArray[totalWords - 2] = l << 3;
    wordArray[totalWords - 1] = l >>> 29;
    return wordArray;
  }

  function wordToHex(value){
    var hex = "";
    for (var count = 0; count <= 3; count++){
      var b = (value >>> (count * 8)) & 255;
      var t = "0" + b.toString(16);
      hex += t.substr(t.length - 2, 2);
    }
    return hex;
  }

  function md5(message){
    message = unescape(encodeURIComponent(message));
    var x = convertStringToWordArray(message);
    var a = 0x67452301, b = 0xEFCDAB89, c = 0x98BADCFE, d = 0x10325476;
    var aa, bb, cc, dd;
    var s11=7,s12=12,s13=17,s14=22, s21=5,s22=9,s23=14,s24=20, s31=4,s32=11,s33=16,s34=23, s41=6,s42=10,s43=15,s44=21;
    for (var k = 0; k < x.length; k += 16){
      aa=a; bb=b; cc=c; dd=d;
      a=FF(a,b,c,d,x[k+0],s11,0xD76AA478); d=FF(d,a,b,c,x[k+1],s12,0xE8C7B756); c=FF(c,d,a,b,x[k+2],s13,0x242070DB); b=FF(b,c,d,a,x[k+3],s14,0xC1BDCEEE);
      a=FF(a,b,c,d,x[k+4],s11,0xF57C0FAF); d=FF(d,a,b,c,x[k+5],s12,0x4787C62A); c=FF(c,d,a,b,x[k+6],s13,0xA8304613); b=FF(b,c,d,a,x[k+7],s14,0xFD469501);
      a=FF(a,b,c,d,x[k+8],s11,0x698098D8); d=FF(d,a,b,c,x[k+9],s12,0x8B44F7AF); c=FF(c,d,a,b,x[k+10],s13,0xFFFF5BB1); b=FF(b,c,d,a,x[k+11],s14,0x895CD7BE);
      a=FF(a,b,c,d,x[k+12],s11,0x6B901122); d=FF(d,a,b,c,x[k+13],s12,0xFD987193); c=FF(c,d,a,b,x[k+14],s13,0xA679438E); b=FF(b,c,d,a,x[k+15],s14,0x49B40821);
      a=GG(a,b,c,d,x[k+1],s21,0xF61E2562); d=GG(d,a,b,c,x[k+6],s22,0xC040B340); c=GG(c,d,a,b,x[k+11],s23,0x265E5A51); b=GG(b,c,d,a,x[k+0],s24,0xE9B6C7AA);
      a=GG(a,b,c,d,x[k+5],s21,0xD62F105D); d=GG(d,a,b,c,x[k+10],s22,0x2441453); c=GG(c,d,a,b,x[k+15],s23,0xD8A1E681); b=GG(b,c,d,a,x[k+4],s24,0xE7D3FBC8);
      a=GG(a,b,c,d,x[k+9],s21,0x21E1CDE6); d=GG(d,a,b,c,x[k+14],s22,0xC33707D6); c=GG(c,d,a,b,x[k+3],s23,0xF4D50D87); b=GG(b,c,d,a,x[k+8],s24,0x455A14ED);
      a=GG(a,b,c,d,x[k+13],s21,0xA9E3E905); d=GG(d,a,b,c,x[k+2],s22,0xFCEFA3F8); c=GG(c,d,a,b,x[k+7],s23,0x676F02D9); b=GG(b,c,d,a,x[k+12],s24,0x8D2A4C8A);
      a=HH(a,b,c,d,x[k+5],s31,0xFFFA3942); d=HH(d,a,b,c,x[k+8],s32,0x8771F681); c=HH(c,d,a,b,x[k+11],s33,0x6D9D6122); b=HH(b,c,d,a,x[k+14],s34,0xFDE5380C);
      a=HH(a,b,c,d,x[k+1],s31,0xA4BEEA44); d=HH(d,a,b,c,x[k+4],s32,0x4BDECFA9); c=HH(c,d,a,b,x[k+7],s33,0xF6BB4B60); b=HH(b,c,d,a,x[k+10],s34,0xBEBFBC70);
      a=HH(a,b,c,d,x[k+13],s31,0x289B7EC6); d=HH(d,a,b,c,x[k+0],s32,0xEAA127FA); c=HH(c,d,a,b,x[k+3],s33,0xD4EF3085); b=HH(b,c,d,a,x[k+6],s34,0x4881D05);
      a=HH(a,b,c,d,x[k+9],s31,0xD9D4D039); d=HH(d,a,b,c,x[k+12],s32,0xE6DB99E5); c=HH(c,d,a,b,x[k+15],s33,0x1FA27CF8); b=HH(b,c,d,a,x[k+2],s34,0xC4AC5665);
      a=II(a,b,c,d,x[k+0],s41,0xF4292244); d=II(d,a,b,c,x[k+7],s42,0x432AFF97); c=II(c,d,a,b,x[k+14],s43,0xAB9423A7); b=II(b,c,d,a,x[k+5],s44,0xFC93A039);
      a=II(a,b,c,d,x[k+12],s41,0x655B59C3); d=II(d,a,b,c,x[k+3],s42,0x8F0CCC92); c=II(c,d,a,b,x[k+10],s43,0xFFEFF47D); b=II(b,c,d,a,x[k+1],s44,0x85845DD1);
      a=II(a,b,c,d,x[k+8],s41,0x6FA87E4F); d=II(d,a,b,c,x[k+15],s42,0xFE2CE6E0); c=II(c,d,a,b,x[k+6],s43,0xA3014314); b=II(b,c,d,a,x[k+13],s44,0x4E0811A1);
      a=II(a,b,c,d,x[k+4],s41,0xF7537E82); d=II(d,a,b,c,x[k+11],s42,0xBD3AF235); c=II(c,d,a,b,x[k+2],s43,0x2AD7D2BB); b=II(b,c,d,a,x[k+9],s44,0xEB86D391);
      a=addUnsigned(a, aa); b=addUnsigned(b, bb); c=addUnsigned(c, cc); d=addUnsigned(d, dd);
    }
    var digest = (wordToHex(a) + wordToHex(b) + wordToHex(c) + wordToHex(d)).toLowerCase();
    return digest;
  }

  // hexToBytes (short: hx)
  function hexToBytes(hex){
    var bytes=[]; for(var i=0;i<hex.length;i+=2){ bytes.push(parseInt(hex.substr(i,2),16)); } return bytes;
  }
  // base64Encode (short: b64)
  function base64Encode(bytes){
    var chars='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    var result=''; var i=0;
    while(i<bytes.length){
      var a=bytes[i++], b=i<bytes.length?bytes[i++]:0, c=i<bytes.length?bytes[i++]:0;
      var bits=(a<<16)|(b<<8)|c;
      result+=chars.charAt((bits>>18)&63)+chars.charAt((bits>>12)&63)+chars.charAt((bits>>6)&63)+chars.charAt(bits&63);
    }
    var padMod = bytes.length%3; if(padMod===1) result=result.slice(0,-2)+'=='; else if(padMod===2) result=result.slice(0,-1)+'=';
    return result;
  }
  // customBase64 (short: cb)
  function customBase64(s){ return s.replace(/\+/g,'9').replace(/\//g,'8').replace(/=/g,'A'); }
  // hashMd5Base64 (short: hm)
  function hashMd5Base64(input){ return customBase64(base64Encode(hexToBytes(md5(input)))); }

  // extractHostname (short: e) and removeSubdomains (short: rs)
  function extractHostname(url, removeSubdomains){
    try{
      var match = url.match(/^(?:https?:\/\/)?(?:[^@\/]+@)?([^:\/]+)/i);
      if(!match) throw new Error('Invalid URL');
      var host = match[1].toLowerCase();
      if(removeSubdomains) host = removeSubdomainsFromHost(host);
      return host;
    }catch(ex){ return url.toLowerCase(); }
  }
  function removeSubdomainsFromHost(host){ var parts = host.split('.'); if(parts.length<2) return host; return parts.slice(-2).join('.'); }

  // validatePasswordPolicy (short: v)
  function validatePasswordPolicy(s, length){
    var sub = s.substring(0,length);
    return /^[a-z]/.test(sub) && /[A-Z]/.test(sub) && /[0-9]/.test(sub);
  }

  // generatePassword (short: gp)
  function generatePassword(master, domain, length, secret, hashRounds){
    length = length || 10; secret = secret || ''; hashRounds = hashRounds || 10;
    var processedDomain = extractHostname(domain, true);
    var inputSeed = master + secret + ':' + processedDomain;
    var current = inputSeed;
    for(var i=0;i<hashRounds;i++){ current = hashMd5Base64(current); }
    var attempts=0; while(!validatePasswordPolicy(current, length)){
      attempts++; current = hashMd5Base64(current);
      if(attempts>1000) throw new Error('Unable to generate valid password after 1000 attempts');
    }
    return current.substring(0,length);
  }

  // createUI (short: ui)
  function createUI(){
    var existing = document.getElementById('sgp-ui'); if(existing) existing.remove();
    var overlay = document.createElement('div'); overlay.id='sgp-ui'; overlay.style.cssText='position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.5);z-index:999999;display:flex;align-items:center;justify-content:center;';
    var panel = document.createElement('div'); panel.style.cssText='background:white;padding:20px;border-radius:8px;box-shadow:0 4px 20px rgba(0,0,0,0.3);max-width:420px;width:90%;font-family:Arial,sans-serif;';
    panel.innerHTML = ''+
      '<h3 style="margin-top:0;color:#333;">SuperGenPass (SGP 2025)</h3>'+
      '<div style="margin-bottom:12px;"><label style="display:block;margin-bottom:4px;font-weight:bold;">Master Password</label><input type="password" id="mp" style="width:100%;padding:8px;border:1px solid #ccc;border-radius:4px;box-sizing:border-box;"></div>'+
      '<div style="margin-bottom:12px;"><label style="display:block;margin-bottom:4px;font-weight:bold;">Domain</label><input type="text" id="dm" value="'+window.location.hostname+'" style="width:100%;padding:8px;border:1px solid #ccc;border-radius:4px;box-sizing:border-box;"></div>'+
      '<div style="margin-bottom:12px;"><label style="display:block;margin-bottom:4px;font-weight:bold;">Secret (optional)</label><input type="text" id="sc" style="width:100%;padding:8px;border:1px solid #ccc;border-radius:4px;box-sizing:border-box;"></div>'+
      '<div style="margin-bottom:16px;"><label style="display:block;margin-bottom:4px;font-weight:bold;">Length</label><input type="number" id="ln" value="10" min="4" max="24" style="width:100%;padding:8px;border:1px solid #ccc;border-radius:4px;box-sizing:border-box;"></div>'+
      '<div style="display:flex;gap:10px;align-items:center;"><button id="gn" style="flex:1;padding:10px;background:#007cba;color:white;border:none;border-radius:4px;cursor:pointer;font-weight:bold;">Generate</button><button id="cl" style="flex:1;padding:10px;background:#666;color:white;border:none;border-radius:4px;cursor:pointer;">Close</button></div>'+
      '<div id="rs" style="margin-top:15px;padding:10px;background:#f5f5f5;border-radius:4px;display:none;">'+
        '<div style="font-weight:bold;margin-bottom:6px;">Generated Password</div>'+
        '<div><input id="pw" type="text" readonly style="width:100%;font-family:monospace;font-size:16px;padding:6px;border:1px solid #ccc;border-radius:4px;" /></div>'+
        '<div style="margin-top:10px;display:flex;gap:10px;align-items:center;justify-content:flex-start;">'+
          '<button id="cp" style="padding:6px 10px;background:#28a745;color:white;border:none;border-radius:4px;cursor:pointer;">Copy to Clipboard</button>'+
        '</div>'+
      '</div>';
    overlay.appendChild(panel); document.body.appendChild(overlay);

    function generate(){
      var master = document.getElementById('mp').value;
      var domain = document.getElementById('dm').value;
      var secret = document.getElementById('sc').value;
      var length = parseInt(document.getElementById('ln').value)||10;
      if(!master){ alert('Please enter a master password'); return; }
      if(!domain){ alert('Please enter a domain'); return; }
      try {
        var pwd = generatePassword(master, domain, length, secret);
        var pwEl = document.getElementById('pw');
        pwEl.value = pwd;
        document.getElementById('rs').style.display='block';
        // Select the visible result: populates the PRIMARY selection on Linux.
        pwEl.focus(); pwEl.select();
      } catch (err) {
        alert('Error generating password: '+err.message);
      }
    }

    document.getElementById('gn').addEventListener('click', generate);
    document.getElementById('cp').addEventListener('click', function(){
      var pw = document.getElementById('pw');
      var p = pw.value;
      // Select first: this is what puts the password into PRIMARY (middle-click
      // paste) on Linux, and execCommand('copy') below needs a selection anyway.
      pw.focus(); pw.select();
      if(navigator.clipboard && navigator.clipboard.writeText){
        navigator.clipboard.writeText(p).catch(function(){ document.execCommand('copy'); });
      } else {
        document.execCommand('copy');
      }
    });
    document.getElementById('cl').addEventListener('click', function(){ overlay.remove(); });
    overlay.addEventListener('click', function(e){ if(e.target===overlay){ overlay.remove(); } });

    var onEnter=function(e){ if((e.key||'')==='Enter'||e.keyCode===13){ e.preventDefault(); generate(); }};
    ['mp','dm','sc','ln'].forEach(function(id){ var el=document.getElementById(id); if(el){ el.addEventListener('keydown', onEnter); }});
    document.getElementById('mp').focus();
  }

  // Launch UI
  createUI();
})();
