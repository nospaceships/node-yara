
import "hash"

rule looks_like_node_js : log store delete {
	meta:
		created_at = 1493332105
		created_by = "Stephen Vickers"
		description = "Identify node binary"
		is_stable = true
	strings:
		$f1 = "_ZN2v812HeapProfiler11GetObjectIdENS_5LocalINS_5ValueEEE"
		$f2 = "ELF"
	condition:
		($f2 at 1) and $f1
}

rule is_libkdb5 {
	condition:
		hash.md5(0, filesize) == "85a44d813d0719e80c49735332ff354b"
}

import "magic"

rule library_archive {
	condition:
		magic.mime_type() == "application/x-object"
}
