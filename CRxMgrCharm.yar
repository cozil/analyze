rule CRxMgrCharm_start
{
	meta:
		script = "log \"struct CRxMgrCharm {\""
	condition:
		true
}

//438 CRxWndCharm * dlg;
//构造函数特征：68 74 33 00 00 D1 EF E8 [4] 83 C4 04 89 45 ?? C6 45 ?? 01 3B C3 74 ?? 6A 01 6A 01 56 68 [4] 6A 5F 57 8B C8 E8 [4] EB ?? 33 C0 50 6A 78 88 5D ?? 89 86 [4] E8
//由于以上特征有多处匹配，无法适用。可以在下面的特征匹配失败时使用这个特征手动搜索
//其中有一处引用了图片：..\\datas\\interface\\DATA\\window_npc\\system_m02.bmp
rule CRxMgrCharm_dlg
{
	meta:
		script = "cmp #pattern1, 1"
		script = "jne _NEXT"
		script = "$result = [@pattern1 + 0x0e]"
		script = "jmp _FINISH"
		script = "_NEXT:"
		script = "$result = [@pattern2 + 0x0e]"
		script = "_FINISH:"
		script = "log \"/*{p:$result}*/    CRxWndCharm * dlg;\""
	strings:
		$pattern1 = { 68 CC 08 00 00 EB ?? 83 F8 26 75 ?? 8B 8E [4] E8 }
		$pattern2 = { 68 9E 09 00 00 EB ?? 83 F8 25 75 ?? 8B 8E [4] E8 }
	condition:
		for any of them : (# == 1)
}


rule CRxMgrCharm_end
{
	meta:
		script = "log }"
		script = "log"
		script = "log"
	condition:
		true
}