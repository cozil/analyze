rule CRxMgrFymap_start
{
	meta:
		script = "Type.as CRxMgrFymap"
		script = "Type.aanc CRxMgrFymap,CRxMgr"
		script = "Type.comment CRxMgrFymap, \"风云地图管理\""
	condition:
		true
}

//22C CRxWnd * dlg_map;
rule CRxMgrFymap_dlg_map
{
	meta:
		script = "$result = [@pattern + 0xf]"
		script = "Type.am CRxMgrFymap,CRxWnd*,dlg_map,0,$result"	
	strings:
		$pattern = { 8B [7] E8 [52] 68 38 01 00 00 ?? 6a 12 68 1d 01 00 00 6a 03 68 0f 01 00 00 [2] E8 }
	condition:
		#pattern == 1
}

//2F0 Point image_offset;
rule CRxMgrFymap_offset
{
	meta:
		script = "$result = [@pattern + 0x13]"
		script = "Type.am CRxMgrFymap,Point,image_offset,0,$result"
		script = "Type.mcomment CRxMgrFymap,image_offset,\"小地图在游戏窗口客户区的像素偏移值x,y，左上角原点\""
	strings:
		$pattern = { E8 [4] 8B 86 [4] 8B 48 ?? 83 C1 05 89 8E [4] 8B 50 ?? 83 C2 15 6A 01 68 [4] 89 96 }
	condition:
		#pattern == 1
}

rule CRxMgrFymap_end
{
	meta:
		script = "Type.print CRxMgrFymap,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}