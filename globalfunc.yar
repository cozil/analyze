rule func_memset
{
	meta:
		script = "$result = @pattern + 0x1c + [@pattern + 0x18]"
		script = "lblset $result, memset__"
	strings:
		$pattern = { 68 C8 00 00 00 [6] 6A 00 C1 EF 06 52 [6] E8 }
	condition:
		#pattern == 1
}

rule func_malloc
{
	meta:
		script = "$result = @pattern + 0x11 + [@pattern + 0xd]"
		script = "lblset $result, malloc__"
	strings:
		$pattern = { 6A 79 E8 [4] 68 F4 23 00 00 E8 [4] 83 C4 14 89 45 ?? C6 45 ?? 09 }
	condition:
		#pattern == 1
}

rule func_CRxWnd_push_gui_object
{
	meta:
		script = "$result = @pattern + 0x7 + [@pattern + 0x3]"
		script = "lblset $result, CRxWnd::push_gui_object"
	strings:
		$pattern = { 6A 00 E8 [10] 6A 01 6A 01 68 1D 01 00 00 6A 0A 6A 3C 68 44 01 00 00 6A 00 }
	condition:
		#pattern == 1
}

rule func_CRxWnd_push_gui_object2
{
	meta:
		script = "$result = @pattern + 0x5 + [@pattern + 0x1]"
		script = "lblset $result, CRxWnd::push_gui_object2"
		script = "$result = @pattern + 0x1d + [@pattern + 0x19]"
		script = "lblset $result, malloc__"
	strings:
		$pattern = { E8 [4] 68 F4 23 00 00 [3] 7D 00 00 00 [3] 0A 01 00 00 E8 [4] 83 C4 04 [6] 06 }
	condition:
		#pattern == 1
}
