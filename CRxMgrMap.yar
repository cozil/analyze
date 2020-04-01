rule CRxMgrMap_start
{
	meta:
		script = "Type.as CRxMgrMap"
		script = "Type.comment CRxMgrMap,\"游戏小地图管理器type=0x2b\""
	condition:
		true
}

//240 CRxWnd * dlg_normal;
rule CRxMgrMap_dlg_normal
{
	meta:
		script = "$result = [@pattern + 0x2c]"
		script = "Type.am CRxMgrMap,CRxWnd*,dlg_normal,0,$result"
		script = "Type.mcomment CRxMgrMap,dlg_normal,\"小尺寸地图窗口\""
	strings:
		$pattern = { C6 [2] 05 [4] 8B [5] 8B [6] 6A 01 ?? 68 [8] E8 [8] 89 [5] C6 [5] 01 8D [6] 68 [4] C6 [2] 03 }
	condition:
		#pattern == 1
}

//244 CRxWnd * dlg_big;
rule CRxMgrMap_dlg_big
{
	meta:
		script = "$result = [@pattern + 0x2c]"
		script = "Type.am CRxMgrMap,CRxWnd*,dlg_big,0,$result"
		script = "Type.mcomment CRxMgrMap,dlg_normal,\"大尺寸地图窗口\""
	strings:
		$pattern = { C6 [2] 06 [4] 8B [5] 8B [6] 6A 01 ?? 68 [8] E8 [8] 89 [5] C6 [5] 01 }
	condition:
		#pattern == 1
}

//514 uint32_t mapid;
rule CRxMgrMap_mapid
{
	meta:
		script = "$result = [@pattern + 0x2]"
		script = "Type.am CRxMgrMap,uint32_t,mapid,0,$result"
	strings:
		$pattern = { 89 [5] 81 ?? E6 03 00 00 0F 87 [6] B8 [5] DA 59 00 00 }
	condition:
		#pattern == 1
}

//584 Point image_offset;
//58c Point image_zoom;
//594 Point image_size;
//59c Point client_offset;
//5a4 Point client_size;
rule CRxMgrMap_others
{
	meta:
		script = "$result = [@pattern + 0x3d]"
		script = "Type.am CRxMgrMap,Point,image_offset,0,$result"
		script = "Type.mcomment CRxMgrMap,image_offset,\"小地图在游戏窗口客户区的像素偏移值x,y，左上角原点\""
		
		script = "Type.am CRxMgrMap,Point,image_zoom,0,$result+8"
		script = "Type.mcomment CRxMgrMap,image_zoom,\"小地图缩放后的像素尺寸\""
		
		script = "Type.am CRxMgrMap,Point,image_size,0,$result+0x10"
		script = "Type.mcomment CRxMgrMap,image_size,\"小地图原始像素尺寸\""
		
		script = "Type.am CRxMgrMap,Point,client_offset,0,$result+0x18"
		script = "Type.mcomment CRxMgrMap,client_offset,\"小地图窗口显示区域距离游戏窗口客户区的像素偏移值x,y，左上角原点\""
		
		script = "Type.am CRxMgrMap,Point,client_size,0,$result+0x20"
		script = "Type.mcomment CRxMgrMap,client_size,\"小地图显示区域像素尺寸\""
		
	strings:
		$pattern = { 6A 05 6A 13 ?? FF ?? A1 [6] 8B [5] 6A 06 6A 14 ?? FF ?? 8B [5] 8B [5] 8D [6] 8D [6] 8B [5] 8D }
	condition:
		#pattern == 1
}

rule CRxMgrMap_end
{
	meta:
		script = "Type.print CRxMgrMap,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}