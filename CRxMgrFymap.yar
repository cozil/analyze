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
		$pattern = { 8B 8E [4] 56 57 E8 [4] 8B 86 [4] 68 F0 03 00 00 C6 80 [4] 01 E8 [4] 83 C4 04 89 45 ?? C6 45 ?? 07 }
	condition:
		#pattern == 1
}

//2F0 int image_offset_x;
//2F4 int image_offset_y;
rule CRxMgrFymap_offset
{
	meta:
		script = "$result = [@pattern + 0x13]"
		script = "Type.am CRxMgrFymap,int,image_offset_x,0,$result"
		script = "$result = [@pattern + 0x26]"
		script = "Type.am CRxMgrFymap,int,image_offset_y,0,$result"	
		script = "Type.mcomment CRxMgrFymap,image_offset_x,\"小地图在游戏窗口客户区的像素偏移值x,y，左上角原点\""
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