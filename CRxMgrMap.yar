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

//514 int mapid;
rule CRxMgrMap_mapid
{
	meta:
		script = "$result = [@pattern + 0x2]"
		script = "Type.am CRxMgrMap,int,mapid,0,$result"
	strings:
		$pattern = { 89 [5] 81 ?? E6 03 00 00 0F 87 [6] B8 [5] DA 59 00 00 }
	condition:
		#pattern == 1
}

rule CRxMgrMap_others
{
	meta:
		script = "$result = [@pattern + 0x3d]"
		script = "Type.am CRxMgrMap,int,image_offset_x,0,$result"
		script = "Type.am CRxMgrMap,int,image_offset_y,0,$result+4"
		script = "Type.mcomment CRxMgrMap,image_offset_x,\"小地图在游戏窗口客户区的像素偏移值x,y，左上角原点\""
		
		script = "Type.am CRxMgrMap,int,image_zoom_width,0,$result+8"
		script = "Type.am CRxMgrMap,int,image_zoom_height,0,$result+0xc"
		script = "Type.mcomment CRxMgrMap,image_zoom_width,\"小地图缩放后的像素尺寸\""
		
		script = "Type.am CRxMgrMap,int,image_width,0,$result+0x10"
		script = "Type.am CRxMgrMap,int,image_height,0,$result+0x14"
		script = "Type.mcomment CRxMgrMap,image_width,\"小地图原始像素尺寸\""
		
		script = "Type.am CRxMgrMap,int,client_offset_x,0,$result+0x18"
		script = "Type.am CRxMgrMap,int,client_offset_y,0,$result+0x1c"
		script = "Type.mcomment CRxMgrMap,client_offset_x,\"小地图窗口显示区域距离游戏窗口客户区的像素偏移值x,y，左上角原点\""
		
		script = "Type.am CRxMgrMap,int,client_view_width,0,$result+0x20"
		script = "Type.am CRxMgrMap,int,client_view_height,0,$result+0x24"
		script = "Type.mcomment CRxMgrMap,client_view_width,\"小地图显示区域像素尺寸\""
		
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