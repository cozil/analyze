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

//rule func_malloc 在func_CRxWnd_push_gui_object2中实现
//{
//	meta:
//		script = "$result = @pattern + 0x11 + [@pattern + 0xd]"
//		script = "lblset $result, malloc__"
//	strings:
//		$pattern = { 6A 79 E8 [4] 68 F4 23 00 00 E8 [4] 83 C4 14 89 45 ?? C6 45 ?? 09 }
//	condition:
//		#pattern == 1
//}

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
		//$pattern = { E8 [4] 68 F4 23 00 00 [3] 7D 00 00 00 [3] 0A 01 00 00 E8 [4] 83 C4 04 [6] 06 } 17015
		$pattern = { E8 [4] 68 [7] 7D 00 00 00 [3] 0A 01 00 00 E8 }
		
	condition:
		#pattern == 1
}


rule func_safe_strcpy
{
	meta:
		script = "$result = @pattern + 0x19 + [@pattern + 0x15]"
		script = "lblset $result,safe_strcpy__"
		script = "$result = @pattern + 0xe + [@pattern + 0xa]"
		script = "lblset $result,load_ybmsg@id"
	strings:
		$pattern = { 6A FF 6A 40 68 5E 05 00 00 E8 [4] 50 68 [4] E8 }
	condition:
		#pattern == 1
}

rule func_CRxList_create
{
	meta:
		script = "$result = @pattern + 0x32 + [@pattern + 0x2e]"
		script = "lblset $result,CRxList::create"
	strings:
		//$pattern = { C6 45 ?? 05 [4] 6A ?? 56 6A 73 6A 00 8B C8 E8 [4] EB ?? 33 C0 A3 } 17015
		$pattern = { 41 [2] 08 [2] 0E [33] 73 ?? 00 [2] E8 [4] EB }
	condition:
		#pattern == 1
}

//CRxApp构造函数
rule CRxApp_create
{
	meta:
		script = "lblset @pattern, \"CRxApp::create\""
	strings:
		//$pattern = { 55 8b ec 6a [10-100] e8 [4] 8d 8b [4] 89 7d ?? c7 03 [4] e8 [4] 68 34 2d 00 00 }	17015
		$pattern = { 55 8b ec 6a [10-100] e8 [4] 8d 8b [4] 89 7d ?? c7 03 [4] e8 [4] c6 83 [4] 00 [6] 00 }
	condition:
		#pattern == 1
}