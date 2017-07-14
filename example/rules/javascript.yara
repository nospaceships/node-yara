
rule javascript {
	strings:
		$s1 = "function"
		
	condition:
		$s1
}

