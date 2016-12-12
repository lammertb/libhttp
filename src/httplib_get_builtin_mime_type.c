/* 
 * Copyright (c) 2016 Lammert Bies
 * Copyright (c) 2013-2016 the Civetweb developers
 * Copyright (c) 2004-2013 Sergey Lyubka
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



#include "httplib_main.h"


static const struct {
	const char *extension;
	size_t ext_len;
	const char *mime_type;
} builtin_mime_types[] = {
	/*
	 * IANA registered MIME types (http://www.iana.org/assignments/media-types)
	 * application types
	 */
	{ ".doc",     4, "application/msword"			},
	{ ".eps",     4, "application/postscript"		},
	{ ".exe",     4, "application/octet-stream"		},
	{ ".js",      3, "application/javascript"		},
	{ ".json",    5, "application/json"			},
	{ ".pdf",     4, "application/pdf"			},
	{ ".ps",      3, "application/postscript"		},
	{ ".rtf",     4, "application/rtf"			},
	{ ".xhtml",   6, "application/xhtml+xml"		},
	{ ".xsl",     4, "application/xml"			},
	{ ".xslt",    5, "application/xml"			},

	/* fonts */
	{ ".ttf",     4, "application/font-sfnt"		},
	{ ".cff",     4, "application/font-sfnt"		},
	{ ".otf",     4, "application/font-sfnt"		},
	{ ".aat",     4, "application/font-sfnt"		},
	{ ".sil",     4, "application/font-sfnt"		},
	{ ".pfr",     4, "application/font-tdpfr"		},
	{ ".woff",    5, "application/font-woff"		},

	/* audio */
	{ ".mp3",     4, "audio/mpeg"				},
	{ ".oga",     4, "audio/ogg"				},
	{ ".ogg",     4, "audio/ogg"				},

	/* image */
	{ ".gif",     4, "image/gif"				},
	{ ".ief",     4, "image/ief"				},
	{ ".jpeg",    5, "image/jpeg"				},
	{ ".jpg",     4, "image/jpeg"				},
	{ ".jpm",     4, "image/jpm"				},
	{ ".jpx",     4, "image/jpx"				},
	{ ".png",     4, "image/png"				},
	{ ".svg",     4, "image/svg+xml"			},
	{ ".tif",     4, "image/tiff"				},
	{ ".tiff",    5, "image/tiff"				},

	/* model */
	{ ".wrl",     4, "model/vrml"				},

	/* text */
	{ ".css",     4, "text/css"				},
	{ ".csv",     4, "text/csv"				},
	{ ".htm",     4, "text/html"				},
	{ ".html",    5, "text/html"				},
	{ ".sgm",     4, "text/sgml"				},
	{ ".shtm",    5, "text/html"				},
	{ ".shtml",   6, "text/html"				},
	{ ".txt",     4, "text/plain"				},
	{ ".xml",     4, "text/xml"				},

	/* video */
	{ ".mov",     4, "video/quicktime"			},
	{ ".mp4",     4, "video/mp4"				},
	{ ".mpeg",    5, "video/mpeg"				},
	{ ".mpg",     4, "video/mpeg"				},
	{ ".ogv",     4, "video/ogg"				},
	{ ".qt",      3, "video/quicktime"			},

	/*
	 * not registered types
	 * (http://reference.sitepoint.com/html/mime-types-full,
	 * http://www.hansenb.pdx.edu/DMKB/dict/tutorials/mime_typ.php, ..)
	 */
	{ ".arj",     4, "application/x-arj-compressed"		},
	{ ".gz",      3, "application/x-gunzip"			},
	{ ".rar",     4, "application/x-arj-compressed"		},
	{ ".swf",     4, "application/x-shockwave-flash"	},
	{ ".tar",     4, "application/x-tar"			},
	{ ".tgz",     4, "application/x-tar-gz"			},
	{ ".torrent", 8, "application/x-bittorrent"		},
	{ ".ppt",     4, "application/x-mspowerpoint"		},
	{ ".xls",     4, "application/x-msexcel"		},
	{ ".zip",     4, "application/x-zip-compressed"		},
	{ ".aac",     4, "audio/aac"				}, /* http://en.wikipedia.org/wiki/Advanced_Audio_Coding */
	{ ".aif",     4, "audio/x-aif"				},
	{ ".m3u",     4, "audio/x-mpegurl"			},
	{ ".mid",     4, "audio/x-midi"				},
	{ ".ra",      3, "audio/x-pn-realaudio"			},
	{ ".ram",     4, "audio/x-pn-realaudio"			},
	{ ".wav",     4, "audio/x-wav"				},
	{ ".bmp",     4, "image/bmp"				},
	{ ".ico",     4, "image/x-icon"				},
	{ ".pct",     4, "image/x-pct"				},
	{ ".pict",    5, "image/pict"				},
	{ ".rgb",     4, "image/x-rgb"				},
	{ ".webm",    5, "video/webm"				}, /* http://en.wikipedia.org/wiki/WebM */
	{ ".asf",     4, "video/x-ms-asf"			},
	{ ".avi",     4, "video/x-msvideo"			},
	{ ".m4v",     4, "video/x-m4v"				},
	{ NULL,       0, NULL					}
};


const char *mg_get_builtin_mime_type( const char *path ) {

	const char *ext;
	size_t i;
	size_t path_len;

	path_len = strlen(path);

	for (i = 0; builtin_mime_types[i].extension != NULL; i++) {
		ext = path + (path_len - builtin_mime_types[i].ext_len);
		if (path_len > builtin_mime_types[i].ext_len
		    && mg_strcasecmp(ext, builtin_mime_types[i].extension) == 0) {
			return builtin_mime_types[i].mime_type;
		}
	}

	return "text/plain";

}  /* mg_get_builtin_mime_type */
