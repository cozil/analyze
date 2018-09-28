//
//CRxWnd中的部分成员偏移分析
//

rule CRxWnd_start
{
	meta:
		script = "Type.as CRxWnd"
		script = "Type.comment CRxWnd,\"窗口基础类 type=0x18\""
	condition:
		true
}

rule CRxWnd_visible
{
	meta:
		script = "$result = byte:[@pattern + 0x06]"
		script = "$result1 = byte:[@pattern + 0x11]"
		script = "cmp $result - $result1,0"
		script = "jz _SUCCESS"
		script = "log \"Invalid offset for CRxWnd::visible\""
		script = "jmp _END"
		script = "_SUCCESS:"
		script = "Type.am CRxWnd,int,visible,0,$result"
		script = "_END:"
	strings:
		$pattern = { 55 8B EC 51 83 79 40 00 [6] 56 C7 41 40 01 00 00 00 }
	condition:
		#pattern == 1
}

rule CRxWnd_flag
{
	meta:
		script = "$result = [@pattern + 0x2e]"
		script = "Type.am CRxWnd,int,flag,0,$result"
		script = "Type.mcomment CRxWnd,flag, \"对于仓库窗口：0 - 个人仓库, 1 - 综合仓库\""
	strings:
		$pattern = { 83 E8 13 [6] 83 E8 03 [9] 83 F8 0B [6] 33 DB 38 9E [4] 0F 84 [4] 89 86 }
	condition:
		#pattern == 1
}

//检测CRxWnd边界并输出
//rule CRxWnd_end
//{
//	meta:
//		script = "$result = [@pattern + 0x06]"
//		script = "Type.am CRxWnd,int,_deleted, $result-0x4"
//		script = "Type.rm CRxWnd,_deleted"
//		script = "Type.print CRxWnd"
//	strings:
//		$pattern = { D4 00 00 00 [31] 0B [9] 83 ?? 04 ?? 00 01 00 00 }
//	condition:
//		#pattern == 1
//}

rule CRxWnd_end
{
	meta:
		script = "Type.print CRxWnd,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}
