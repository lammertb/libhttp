/* 
 * Copyright (c) 2016 Lammert Bies
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
 *
 * ============
 * Release: 2.0
 */

#include "httplib_main.h"

#define NUM_MIME_TYPES		((int)(sizeof(builtin_mime_types)/sizeof(builtin_mime_types[0])))

static const struct {
	const char *extension;
	const char *mime_type;
} builtin_mime_types[] = {
	{ ".3dm",	"x-world/x-3dmf"					},
	{ ".3dmf",	"x-world/x-3dmf"					},

	{ ".a",		"application/octet-stream"				},
	{ ".aab",	"application/x-authorware-bin"				},
	{ ".aac",	"audio/aac"						},
	{ ".aam",	"application/x-authorware-map"				},
	{ ".aas",	"application/x-authorware-seg"				},
	{ ".aat",	"application/font-sfnt"					},
	{ ".abc",	"text/vnd.abc"						},
	{ ".acgi",	"text/html"						},
	{ ".afl",	"video/animaflex"					},
	{ ".ai",	"application/postscript"				},
	{ ".aif",	"audio/x-aiff"						},
	{ ".aifc",	"audio/x-aiff"						},
	{ ".aiff",	"audio/x-aiff"						},
	{ ".aim",	"application/x-aim"					},
	{ ".aip",	"text/x-audiosoft-intra"				},
	{ ".ani",	"application/x-navi-animation"				},
	{ ".aos",	"application/x-nokia-9000-communicator-add-on-software"	},
	{ ".aps",	"application/mime"					},
	{ ".arc",	"application/octet-stream"				},
	{ ".arj",	"application/arj"					},
	{ ".art",	"image/x-jg"						},
	{ ".asf",	"video/x-ms-asf"	 				},
	{ ".asm",	"text/x-asm",						},
	{ ".asp",	"text/asp",						},
	{ ".asx",	"video/x-ms-asf"					},
	{ ".au",	"audio/x-au"						},
	{ ".avi",	"video/x-msvideo"					},
	{ ".avs",	"video/avs-video"					},

	{ ".bcpio",	"application/x-bcpio"					},
	{ ".bin",	"application/x-binary"					},
	{ ".bm",	"image/bmp"						},
	{ ".bmp",	"image/bmp"						},
	{ ".boo",	"application/book"					},
	{ ".book",	"application/book"					},
	{ ".boz",	"application/x-bzip2"					},
	{ ".bsh",	"application/x-bsh"					},
	{ ".bz",	"application/x-bzip"					},
	{ ".bz2",	"application/x-bzip2"					},

	{ ".c",		"text/x-c"						},
	{ ".c++",	"text/x-c"						},
	{ ".cat",	"application/vnd.ms-pki.seccat"				},
	{ ".cc",	"text/x-c"						},
	{ ".ccad",	"application/clariscad"					},
	{ ".cco",	"application/x-cocoa"					},
	{ ".cdf",	"application/x-cdf"					},
	{ ".cer",	"application/pkix-cert"					},
	{ ".cff",	"application/font-sfnt"					},
	{ ".cha",	"application/x-chat"					},
	{ ".chat",	"application/x-chat"					},
	{ ".class",	"application/x-java-class"				},
	{ ".com",	"application/octet-stream"				},
	{ ".conf",	"text/plain"						},
	{ ".cpio",	"application/x-cpio"					},
	{ ".cpp",	"text/x-c"						},
	{ ".cpt",	"application/x-compactpro"				},
	{ ".crl",	"application/pkcs-crl"					},
	{ ".crt",	"application/x-x509-user-cert"				},
	{ ".csh",	"text/x-script.csh"					},
	{ ".css",	"text/css"						},
	{ ".csv",	"text/csv"						},
	{ ".cxx",	"text/plain"						},

	{ ".dcr",	"application/x-director"				},
	{ ".deepv",	"application/x-deepv"					},
	{ ".def",	"text/plain"						},
	{ ".der",	"application/x-x509-ca-cert"				},
	{ ".dif",	"video/x-dv"						},
	{ ".dir",	"application/x-director"				},
	{ ".dl",	"video/x-dl"						},
	{ ".dll",	"application/octet-stream"				},
	{ ".doc",	"application/msword"					},
	{ ".dot",	"application/msword"					},
	{ ".dp",	"application/commonground"				},
	{ ".drw",	"application/drafting"					},
	{ ".dump",	"application/octet-stream"				},
	{ ".dv",	"video/x-dv"						},
	{ ".dvi",	"application/x-dvi"					},
	{ ".dwf",	"model/vnd.dwf"						},
	{ ".dwg",	"image/vnd.dwg"						},
	{ ".dxf",	"image/vnd.dwg"						},
	{ ".dxr",	"application/x-director"				},

	{ ".el",	"text/x-script.elisp"					},
	{ ".elc",	"application/x-bytecode.elisp"				},
	{ ".env",	"application/x-envoy"					},
	{ ".eps",	"application/postscript"				},
	{ ".es",	"application/x-esrehber"				},
	{ ".etx",	"text/x-setext"						},
	{ ".evy",	"application/x-envoy"					},
	{ ".exe",	"application/octet-stream"				},

	{ ".f",		"text/x-fortran"					},
	{ ".f77",	"text/x-fortran"					},
	{ ".f90",	"text/x-fortran"					},
	{ ".fdf",	"application/vnd.fdf"					},
	{ ".fif",	"image/fif"						},
	{ ".fli",	"video/x-fli"						},
	{ ".flo",	"image/florian"						},
	{ ".flx",	"text/vnd.fmi.flexstor"					},
	{ ".fmf",	"video/x-atomic3d-feature"				},
	{ ".for",	"text/x-fortran"					},
	{ ".fpx",	"image/vnd.fpx"						},
	{ ".frl",	"application/freeloader"				},
	{ ".funk",	"audio/make"						},

	{ ".g",		"text/plain"						},
	{ ".g3",	"image/g3fax"						},
	{ ".gif",	"image/gif"						},
	{ ".gl",	"video/x-gl"						},
	{ ".gsd",	"audio/x-gsm"						},
	{ ".gsm",	"audio/x-gsm"						},
	{ ".gsp",	"application/x-gsp"					},
	{ ".gss",	"application/x-gss"					},
	{ ".gtar",	"application/x-gtar"					},
	{ ".gz",	"application/x-gzip"					},

	{ ".h",		"text/x-h"						},
	{ ".hdf",	"application/x-hdf"					},
	{ ".help",	"application/x-helpfile"				},
	{ ".hgl",	"application/vnd.hp-hpgl"				},
	{ ".hh",	"text/x-h"						},
	{ ".hlb",	"text/x-script"						},
	{ ".hlp",	"application/x-helpfile"				},
	{ ".hpg",	"application/vnd.hp-hpgl"				},
	{ ".hpgl",	"application/vnd.hp-hpgl"				},
	{ ".hqx",	"application/binhex"					},
	{ ".hta",	"application/hta"					},
	{ ".htc",	"text/x-component"					},
	{ ".htm",	"text/html"						},
	{ ".html",	"text/html"						},
	{ ".htmls",	"text/html"						},
	{ ".htt",	"text/webviewhtml"					},
	{ ".htx",	"text/html"						},

	{ ".ice",	"x-conference/x-cooltalk"				},
	{ ".ico",	"image/x-icon"						},
	{ ".idc",	"text/plain"						},
	{ ".ief",	"image/ief"						},
	{ ".iefs",	"image/ief"						},
	{ ".iges",	"model/iges"						},
	{ ".igs",	"model/iges"						},
	{ ".ima",	"application/x-ima"					},
	{ ".imap",	"application/x-httpd-imap"				},
	{ ".inf",	"application/inf"					},
	{ ".ins",	"application/x-internett-signup"			},
	{ ".ip",	"application/x-ip2"					},
	{ ".isu",	"video/x-isvideo"					},
	{ ".it",	"audio/it"						},
	{ ".iv",	"application/x-inventor"				},
	{ ".ivr",	"i-world/i-vrml"					},
	{ ".ivy",	"application/x-livescreen"				},

	{ ".jam",	"audio/x-jam"						},
	{ ".jav",	"text/x-java-source"					},
	{ ".java",	"text/x-java-source"					},
	{ ".jcm",	"application/x-java-commerce"				},
	{ ".jfif",	"image/jpeg"						},
	{ ".jfif-tbnl",	"image/jpeg"						},
	{ ".jpe",	"image/jpeg"						},
	{ ".jpeg",	"image/jpeg"						},
	{ ".jpg",	"image/jpeg"						},
	{ ".jpm",	"image/jpm"						},
	{ ".jps",	"image/x-jps"						},
	{ ".jpx",	"image/jpx"						},
	{ ".js",	"application/x-javascript"				},
	{ ".json",	"application/json"					},
	{ ".jut",	"image/jutvision"					},

	{ ".kar",	"music/x-karaoke"					},
	{ ".kml",	"application/vnd.google-earth.kml+xml"			},
	{ ".kmz",	"application/vnd.google-earth.kmz"			},
	{ ".ksh",	"text/x-script.ksh"					},

	{ ".la",	"audio/x-nspaudio"					},
	{ ".lam",	"audio/x-liveaudio"					},
	{ ".latex",	"application/x-latex"					},
	{ ".lha",	"application/x-lha"					},
	{ ".lhx",	"application/octet-stream"				},
	{ ".lib",	"application/octet-stream"				},
	{ ".list",	"text/plain"						},
	{ ".lma",	"audio/x-nspaudio"					},
	{ ".log",	"text/plain"						},
	{ ".lsp",	"text/x-script.lisp"					},
	{ ".lst",	"text/plain"						},
	{ ".lsx",	"text/x-la-asf"						},
	{ ".ltx",	"application/x-latex"					},
	{ ".lzh",	"application/x-lzh"					},
	{ ".lzx",	"application/x-lzx"					},

	{ ".m",		"text/x-m"						},
	{ ".m1v",	"video/mpeg"						},
	{ ".m2a",	"audio/mpeg"						},
	{ ".m2v",	"video/mpeg"						},
	{ ".m3u",	"audio/x-mpegurl"					},
	{ ".m4v",	"video/x-m4v"						},
	{ ".man",	"application/x-troff-man"				},
	{ ".map",	"application/x-navimap"					},
	{ ".mar",	"text/plain"						},
	{ ".mbd",	"application/mbedlet"					},
	{ ".mc$",	"application/x-magic-cap-package-1.0"			},
	{ ".mcd",	"application/x-mathcad"					},
	{ ".mcf",	"text/mcf"						},
	{ ".mcp",	"application/netmc"					},
	{ ".me",	"application/x-troff-me"				},
	{ ".mht",	"message/rfc822"					},
	{ ".mhtml",	"message/rfc822"					},
	{ ".mid",	"audio/x-midi"						},
	{ ".midi",	"audio/x-midi"						},
	{ ".mif",	"application/x-mif"					},
	{ ".mime",	"www/mime"						},
	{ ".mjf",	"audio/x-vnd.audioexplosion.mjuicemediafile"		},
	{ ".mjpg",	"video/x-motion-jpeg"					},
	{ ".mm",	"application/base64"					},
	{ ".mme",	"application/base64"					},
	{ ".mod",	"audio/x-mod"						},
	{ ".moov",	"video/quicktime"					},
	{ ".mov",	"video/quicktime"					},
	{ ".movie",	"video/x-sgi-movie"					},
	{ ".mp2",	"video/x-mpeg"						},
	{ ".mp3",	"audio/x-mpeg-3"					},
	{ ".mp4",	"video/mp4"						},
	{ ".mpa",	"audio/mpeg"						},
	{ ".mpc",	"application/x-project"					},
	{ ".mpeg",	"video/mpeg"						},
	{ ".mpg",	"video/mpeg"						},
	{ ".mpga",	"audio/mpeg"						},
	{ ".mpp",	"application/vnd.ms-project"				},
	{ ".mpt",	"application/x-project"					},
	{ ".mpv",	"application/x-project"					},
	{ ".mpx",	"application/x-project"					},
	{ ".mrc",	"application/marc"					},
	{ ".ms",	"application/x-troff-ms"				},
	{ ".mv",	"video/x-sgi-movie"					},
	{ ".my",	"audio/make"						},
	{ ".mzz",	"application/x-vnd.audioexplosion.mzz"			},

	{ ".nap",	"image/naplps"						},
	{ ".naplps",	"image/naplps"						},
	{ ".nc",	"application/x-netcdf"					},
	{ ".ncm",	"application/vnd.nokia.configuration-message"		},
	{ ".nif",	"image/x-niff"						},
	{ ".niff",	"image/x-niff"						},
	{ ".nix",	"application/x-mix-transfer"				},
	{ ".nsc",	"application/x-conference"				},
	{ ".nvd",	"application/x-navidoc"					},

	{ ".o",		"application/octet-stream"				},
	{ ".obj",	"application/octet-stream"				},
	{ ".oda",	"application/oda"					},
	{ ".oga",	"audio/ogg"						},
	{ ".ogg",	"audio/ogg"						},
	{ ".ogv",	"video/ogg"						},
	{ ".omc",	"application/x-omc"					},
	{ ".omcd",	"application/x-omcdatamaker"				},
	{ ".omcr",	"application/x-omcregerator"				},
	{ ".otf",	"application/font-sfnt"					},

	{ ".p",		"text/x-pascal"						},
	{ ".p10",	"application/x-pkcs10"					},
	{ ".p12",	"application/x-pkcs12"					},
	{ ".p7a",	"application/x-pkcs7-signature"				},
	{ ".p7c",	"application/x-pkcs7-mime"				},
	{ ".p7m",	"application/x-pkcs7-mime"				},
	{ ".p7r",	"application/x-pkcs7-certreqresp"			},
	{ ".p7s",	"application/pkcs7-signature"				},
	{ ".part",	"application/pro_eng"					},
	{ ".pas",	"text/x-pascal"						},
	{ ".pbm",	"image/x-portable-bitmap"				},
	{ ".pcl",	"application/vnd.hp-pcl"				},
	{ ".pct",	"image/x-pct"						},
	{ ".pcx",	"image/x-pcx"						},
	{ ".pdb",	"chemical/x-pdb"					},
	{ ".pdf",	"application/pdf"					},
	{ ".pfr",	"application/font-tdpfr"				},
	{ ".pfunk",	"audio/make"						},
	{ ".pgm",	"image/x-portable-greymap"				},
	{ ".pic",	"image/pict"						},
	{ ".pict",	"image/pict"						},
	{ ".pkg",	"application/x-newton-compatible-pkg"			},
	{ ".pko",	"application/vnd.ms-pki.pko"				},
	{ ".pl",	"text/x-script.perl"					},
	{ ".plx",	"application/x-pixelscript"				},
	{ ".pm",	"text/x-script.perl-module"				},
	{ ".pm4",	"application/x-pagemaker"				},
	{ ".pm5",	"application/x-pagemaker"				},
	{ ".png",	"image/png"						},
	{ ".pnm",	"image/x-portable-anymap"				},
	{ ".pot",	"application/vnd.ms-powerpoint"				},
	{ ".pov",	"model/x-pov"						},
	{ ".ppa",	"application/vnd.ms-powerpoint"				},
	{ ".ppm",	"image/x-portable-pixmap"				},
	{ ".pps",	"application/vnd.ms-powerpoint"				},
	{ ".ppt",	"application/vnd.ms-powerpoint"				},
	{ ".ppz",	"application/vnd.ms-powerpoint"				},
	{ ".pre",	"application/x-freelance"				},
	{ ".prt",	"application/pro_eng"					},
	{ ".ps",	"application/postscript"				},
	{ ".psd",	"application/octet-stream"				},
	{ ".pvu",	"paleovu/x-pv"						},
	{ ".pwz",	"application/vnd.ms-powerpoint"				},
	{ ".py",	"text/x-script.python"					},
	{ ".pyc",	"application/x-bytecode.python"				},

	{ ".qcp",	"audio/vnd.qcelp"					},
	{ ".qd3",	"x-world/x-3dmf"					},
	{ ".qd3d",	"x-world/x-3dmf"					},
	{ ".qif",	"image/x-quicktime"					},
	{ ".qt",	"video/quicktime"					},
	{ ".qtc",	"video/x-qtc"						},
	{ ".qti",	"image/x-quicktime"					},
	{ ".qtif",	"image/x-quicktime"					},

	{ ".ra",	"audio/x-pn-realaudio"					},
	{ ".ram",	"audio/x-pn-realaudio"					},
	{ ".rar",	"application/x-arj-compressed"				},
	{ ".ras",	"image/x-cmu-raster"					},
	{ ".rast",	"image/cmu-raster"					},
	{ ".rexx",	"text/x-script.rexx"					},
	{ ".rf",	"image/vnd.rn-realflash"				},
	{ ".rgb",	"image/x-rgb"						},
	{ ".rm",	"audio/x-pn-realaudio"					},
	{ ".rmi",	"audio/mid"						},
	{ ".rmm",	"audio/x-pn-realaudio"					},
	{ ".rmp",	"audio/x-pn-realaudio"					},
	{ ".rng",	"application/vnd.nokia.ringing-tone"			},
	{ ".rnx",	"application/vnd.rn-realplayer"				},
	{ ".roff",	"application/x-troff"					},
	{ ".rp",	"image/vnd.rn-realpix"					},
	{ ".rpm",	"audio/x-pn-realaudio-plugin"				},
	{ ".rt",	"text/vnd.rn-realtext"					},
	{ ".rtf",	"application/x-rtf"					},
	{ ".rtx",	"application/x-rtf"					},
	{ ".rv",	"video/vnd.rn-realvideo"				},

	{ ".s",		"text/x-asm"						},
	{ ".s3m",	"audio/s3m"						},
	{ ".saveme",	"application/octet-stream"				},
	{ ".sbk",	"application/x-tbook"					},
	{ ".scm",	"text/x-script.scheme"					},
	{ ".sdml",	"text/plain"						},
	{ ".sdp",	"application/x-sdp"					},
	{ ".sdr",	"application/sounder"					},
	{ ".sea",	"application/x-sea"					},
	{ ".set",	"application/set"					},
	{ ".sgm",	"text/x-sgml"						},
	{ ".sgml",	"text/x-sgml"						},
	{ ".sh",	"text/x-script.sh"					},
	{ ".shar",	"application/x-shar"					},
	{ ".shtm",	"text/html"						},
	{ ".shtml",	"text/html"						},
	{ ".sid",	"audio/x-psid"						},
	{ ".sil",	"application/font-sfnt"					},
	{ ".sit",	"application/x-sit"					},
	{ ".skd",	"application/x-koan"					},
	{ ".skm",	"application/x-koan"					},
	{ ".skp",	"application/x-koan"					},
	{ ".skt",	"application/x-koan"					},
	{ ".sl",	"application/x-seelogo"					},
	{ ".smi",	"application/smil"					},
	{ ".smil",	"application/smil"					},
	{ ".snd",	"audio/x-adpcm"						},
	{ ".so",	"application/octet-stream"				},
	{ ".sol",	"application/solids"					},
	{ ".spc",	"text/x-speech"						},
	{ ".spl",	"application/futuresplash"				},
	{ ".spr",	"application/x-sprite"					},
	{ ".sprite",	"application/x-sprite"					},
	{ ".src",	"application/x-wais-source"				},
	{ ".ssi",	"text/x-server-parsed-html"				},
	{ ".ssm",	"application/streamingmedia"				},
	{ ".sst",	"application/vnd.ms-pki.certstore"			},
	{ ".step",	"application/step"					},
	{ ".stl",	"application/vnd.ms-pki.stl"				},
	{ ".stp",	"application/step"					},
	{ ".sv4cpio",	"application/x-sv4cpio"					},
	{ ".sv4crc",	"application/x-sv4crc"					},
	{ ".svf",	"image/x-dwg"						},
	{ ".svg",	"image/svg+xml"						},
	{ ".svr",	"x-world/x-svr"						},
	{ ".swf",	"application/x-shockwave-flash"				},

	{ ".t",		"application/x-troff"					},
	{ ".talk",	"text/x-speech"						},
	{ ".tar",	"application/x-tar"					},
	{ ".tbk",	"application/x-tbook"					},
	{ ".tcl",	"text/x-script.tcl"					},
	{ ".tcsh",	"text/x-script.tcsh"					},
	{ ".tex",	"application/x-tex"					},
	{ ".texi",	"application/x-texinfo"					},
	{ ".texinfo",	"application/x-texinfo"					},
	{ ".text",	"text/plain"						},
	{ ".tgz",	"application/x-compressed"				},
	{ ".tif",	"image/x-tiff"						},
	{ ".tiff",	"image/x-tiff"						},
	{ ".torrent",	"application/x-bittorrent"				},
	{ ".tr",	"application/x-troff"					},
	{ ".tsi",	"audio/tsp-audio"					},
	{ ".tsp",	"audio/tsplayer"					},
	{ ".tsv",	"text/tab-separated-values"				},
	{ ".ttf",	"application/font-sfnt"					},
	{ ".turbot",	"image/florian"						},
	{ ".txt",	"text/plain"						},

	{ ".uil",	"text/x-uil"						},
	{ ".uni",	"text/uri-list"						},
	{ ".unis",	"text/uri-list"						},
	{ ".unv",	"application/i-deas"					},
	{ ".uri",	"text/uri-list"						},
	{ ".uris",	"text/uri-list"						},
	{ ".ustar",	"application/x-ustar"					},
	{ ".uu",	"text/x-uuencode"					},
	{ ".uue",	"text/x-uuencode"					},

	{ ".vcd",	"application/x-cdlink"					},
	{ ".vcs",	"text/x-vcalendar"					},
	{ ".vda",	"application/vda"					},
	{ ".vdo",	"video/vdo"						},
	{ ".vew",	"application/groupwise"					},
	{ ".viv",	"video/vnd.vivo"					},
	{ ".vivo",	"video/vnd.vivo"					},
	{ ".vmd",	"application/vocaltec-media-desc"			},
	{ ".vmf",	"application/vocaltec-media-file"			},
	{ ".voc",	"audio/x-voc"						},
	{ ".vos",	"video/vosaic"						},
	{ ".vox",	"audio/voxware"						},
	{ ".vqe",	"audio/x-twinvq-plugin"					},
	{ ".vqf",	"audio/x-twinvq"					},
	{ ".vql",	"audio/x-twinvq-plugin"					},
	{ ".vrml",	"model/vrml"						},
	{ ".vrt",	"x-world/x-vrt"						},
	{ ".vsd",	"application/x-visio"					},
	{ ".vst",	"application/x-visio"					},
	{ ".vsw",	"application/x-visio"					},

	{ ".w60",	"application/wordperfect6.0"				},
	{ ".w61",	"application/wordperfect6.1"				},
	{ ".w6w",	"application/msword"					},
	{ ".wav",	"audio/x-wav"						},
	{ ".wb1",	"application/x-qpro"					},
	{ ".wbmp",	"image/vnd.wap.wbmp"					},
	{ ".web",	"application/vnd.xara"					},
	{ ".webm",	"video/webm"						},
	{ ".wiz",	"application/msword"					},
	{ ".wk1",	"application/x-123"					},
	{ ".wmf",	"windows/metafile"					},
	{ ".wml",	"text/vnd.wap.wml"					},
	{ ".wmlc",	"application/vnd.wap.wmlc"				},
	{ ".wmls",	"text/vnd.wap.wmlscript"				},
	{ ".wmlsc",	"application/vnd.wap.wmlscriptc"			},
	{ ".woff",	"application/font-woff"					},
	{ ".word",	"application/msword"					},
	{ ".wp",	"application/wordperfect"				},
	{ ".wp5",	"application/wordperfect"				},
	{ ".wp6",	"application/wordperfect"				},
	{ ".wpd",	"application/wordperfect"				},
	{ ".wq1",	"application/x-lotus"					},
	{ ".wri",	"application/x-wri"					},
	{ ".wrl",	"model/vrml"						},
	{ ".wrz",	"model/vrml"						},
	{ ".wsc",	"text/scriplet"						},
	{ ".wsrc",	"application/x-wais-source"				},
	{ ".wtk",	"application/x-wintalk"					},

	{ ".x-png",	"image/png"						},
	{ ".xbm",	"image/x-xbm"						},
	{ ".xdr",	"video/x-amt-demorun"					},
	{ ".xgz",	"xgl/drawing"						},
	{ ".xhtml",	"application/xhtml+xml"					},
	{ ".xif",	"image/vnd.xiff"					},
	{ ".xl",	"application/vnd.ms-excel"				},
	{ ".xla",	"application/vnd.ms-excel"				},
	{ ".xlb",	"application/vnd.ms-excel"				},
	{ ".xlc",	"application/vnd.ms-excel"				},
	{ ".xld",	"application/vnd.ms-excel"				},
	{ ".xlk",	"application/vnd.ms-excel"				},
	{ ".xll",	"application/vnd.ms-excel"				},
	{ ".xlm",	"application/vnd.ms-excel"				},
	{ ".xls",	"application/vnd.ms-excel"				},
	{ ".xlt",	"application/vnd.ms-excel"				},
	{ ".xlv",	"application/vnd.ms-excel"				},
	{ ".xlw",	"application/vnd.ms-excel"				},
	{ ".xm",	"audio/xm"						},
	{ ".xml",	"text/xml"						},
	{ ".xmz",	"xgl/movie"						},
	{ ".xpix",	"application/x-vnd.ls-xpix"				},
	{ ".xpm",	"image/x-xpixmap"					},
	{ ".xsl",	"application/xml"					},
	{ ".xslt",	"application/xml"					},
	{ ".xsr",	"video/x-amt-showrun"					},
	{ ".xwd",	"image/x-xwd"						},
	{ ".xyz",	"chemical/x-pdb"					},

	{ ".z",		"application/x-compressed"				},
	{ ".zip",	"application/x-zip-compressed"				},
	{ ".zoo",	"application/octet-stream"				},
	{ ".zsh",	"text/x-script.zsh"					},
};



/*
 * const char *httplib_get_builtin_mime_type( const char *path );
 *
 * The function httplib_get_builtin_mime_type() returns the mime type
 * associated with the file with a given extension which is passed as a
 * parameter. The function performs a binary search through the list of MIME
 * types which is very efficient and only needs 10 steps for 1000 items in the
 * list or 20 steps for 1000000 items.
 *
 * If no matching file extension could be found in the list, the default value
 * of "text/plain" is returned instead.
 */

const char *httplib_get_builtin_mime_type( const char *path ) {

	int start;
	int eind;
	int midden;
	int retval;
	const char *ext;
	size_t path_len;

	if ( path == NULL ) return "text/plain";

	path_len = strlen( path );
	while ( path_len > 1  &&  path[path_len-1] != '.' ) path_len--;

	if ( path_len <= 1 ) return "text/plain";

	ext = & path[path_len-1];

	start = 0;
	eind  = NUM_MIME_TYPES;

	while ( eind-start > 1 ) {

		midden = (start+eind) >> 1;
		retval = httplib_strcasecmp( ext, builtin_mime_types[midden].extension );

		if      ( retval == 0 ) return builtin_mime_types[midden].mime_type;
		else if ( retval <  0 ) eind  = midden;
		else                    start = midden;
	}

	if ( ! httplib_strcasecmp( ext, builtin_mime_types[start].extension ) ) return builtin_mime_types[start].mime_type;

	return "text/plain";

}  /* httplib_get_builtin_mime_type */



/*
 * const char *XX_httplib_builtin_mime_ext( int idx );
 *
 * The function XX_httplib_builtin_mime_ext() returns the file extension of
 * a MIME type as stored in a specific location in the list with MIME types.
 *
 * If the index is invalid, NULL is returned.
 */

const char *XX_httplib_builtin_mime_ext( int idx ) {

	if ( idx <  0              ) return NULL;
	if ( idx >= NUM_MIME_TYPES ) return NULL;

	return builtin_mime_types[idx].extension;

}  /* XX_httplib_builtin_mime_ext */



/*
 * const char *XX_httplib_builtin_mime_type( int idx );
 *
 * The function XX_httplib_builtin_mime_type() returns the MIME type of of a
 * record stored in a specific location in the list with MIME types.
 *
 * If the index is invalid, NULL is returned.
 */

const char *XX_httplib_builtin_mime_type( int idx ) {

	if ( idx <  0              ) return NULL;
	if ( idx >= NUM_MIME_TYPES ) return NULL;

	return builtin_mime_types[idx].mime_type;

}  /* XX_httplib_builtin_mime_type */
