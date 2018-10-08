
//
//CRxMgrNpc部分成员偏移分析
//

rule CRxMgrNpc_start
{
	meta:
		script = "Type.as CRxMgrNpc"
		script = "Type.aanc CRxMgrNpc,CRxMgr"
		script = "Type.comment CRxMgrNpc,\"NPC管理\""
		script = "Type.ad CRxMgrNpc,\"inline void click_close() {{ click(0x5a); }}\""
		script = "Type.ad CRxMgrNpc,\"inline void click_menu_item(int id) {{ click(0x5b+id); }} //id:[0,4]\""
	condition:
		true
}

//228 CRxMgrShop * mgr_shop
rule CRxMgrNpc_mgr_shop
{
	meta:
		script = "$result = [@pattern + 0x34]"
		script = "Type.am CRxMgrNpc,CRxMgrShop*,mgr_shop,0,$result"
		script = "Type.mcomment CRxMgrNpc,mgr_shop,\"NPC商店管理\""
	strings:
		//offset:0x4b
		//$pattern = { 83 C1 03 69 C9 [4] 81 C1 [60] 50 51 8B 8A [4] E8 [4] 83 C6 04 4F }
		//offset:0x34
		$pattern = { 68 58 02 00 00 89 79 ?? E8 [4] 83 C4 04 89 85 [4] C6 45 ?? 13 3B C3 74 ?? 56 8B C8 E8 [4] EB ?? 33 C0 68 48 02 00 00 88 5D ?? 89 86 [4] E8 }
	condition:
		#pattern == 1	
}

//22c CRxMgrSxstone * mgr_sxstone;
rule CRxMgrNpc_mgr_sxstone
{
	meta:
		script = "$result = [@pattern + 0x3a]"
		script = "Type.am CRxMgrNpc,CRxMgrSxstone*,mgr_sxstone,0,$result"
		script = "Type.mcomment CRxMgrNpc,mgr_sxstone,\"属性石合成管理\""
	strings:
		//offset:0x49
		//$pattern = { 6A 65 8B CE E8 [4] 6A 00 E8 [4] 8B 95 [4] 8B 02 83 C4 04 50 8B CE E8 [4] E9 [4] D9 05 [4] E8 [4] D9 05 [4] 50 E8 [4] 8B 0D [4] 50 51 8B 8E [4] E8 }
		//offset:0x3a
		$pattern = { 68 48 02 00 00 88 5D ?? 89 86 [4] E8 [4] 83 C4 04 89 85 [4] C6 45 ?? 14 3B C3 74 ?? 56 8B C8 E8 [4] EB ?? 33 C0 68 40 02 00 00 88 5D ?? 89 86 [4] E8 }
	condition:
		#pattern == 1	
}

//230 CRxMgrDepot * mgr_depot;
rule CRxMgrNpc_mgr_depot
{
	meta:
		script = "$result = [@pattern + 0x3a]"
		script = "Type.am CRxMgrNpc,CRxMgrDepot*,mgr_depot,0,$result"
		script = "Type.mcomment CRxMgrNpc,mgr_depot,\"仓库管理\""
	strings:
		//offset:0x4e
		//$pattern = { 6A 04 6A 01 E8 [4] A1 [4] 6A 00 50 8B CE E8 [4] 8B 95 [4] 8B 02 50 8B CE E8 [4] E9 [4] D9 05 [4] E8 [4] D9 05 [4] 50 E8 [4] 8B 0D [4] 50 51 8B 8E [4] E8 }
		//offset:0x3a
		$pattern = { 68 40 02 00 00 88 5D ?? 89 86 [4] E8 [4] 83 C4 04 89 85 [4] C6 45 ?? 15 3B C3 74 ?? 56 8B C8 E8 [4] EB ?? 33 C0 68 44 02 00 00 88 5D ?? 89 86 [4] E8 }
	condition:
		#pattern == 1	
}

//238 CRxMgrUnite * mgr_unite;
//23c CRxMgrStrong * mgr_strong;
rule CRxMgrNpc_mgr_unite
{
	meta:
		script = "$result = [@pattern + 0x0c]"
		script = "Type.am CRxMgrNpc,CRxMgrUnite*,mgr_unite,0,$result"
		script = "Type.mcomment CRxMgrNpc,mgr_unite,\"合成石合成管理\""
		script = "$result = [@pattern + 0x3c]"
		script = "Type.am CRxMgrNpc,CRxMgrStrong*,mgr_strong,0,$result"
		script = "Type.mcomment CRxMgrNpc,mgr_strong,\"强化管理\""
	strings:
		$pattern = { 33 C0 68 44 02 00 00 88 5D ?? 89 86 [4] E8 [4] 83 C4 04 89 85 [4] C6 45 ?? 17 3B C3 74 ?? 56 8B C8 E8 [4] EB ?? 33 C0 68 84 02 00 00 88 5D ?? 89 86 [4] E8 }
	condition:
		#pattern == 1	
}




//27C CRxMgrPk * mgr_pk;
rule CRxMgrNpc_mgr_pk
{
	meta:
		script = "$result = [@pattern + 0x3a]"
		script = "Type.am CRxMgrNpc,CRxMgrPk*,mgr_pk,0,$result"
		script = "Type.mcomment CRxMgrNpc,mgr_strong,\"PK管理\""
	strings:
		//offset:0x0e
		//$pattern = { 8B 15 [4] 8B 82 [4] 8B 88 [4] C6 81 [4] 00 FF D3 89 86 [4] 39 3D [4] 75 ?? 8B 15 [4] 57 6A 31 52 }
		//offset:0x3a
		$pattern = { 68 88 0A 00 00 88 5D ?? 89 86 [4] E8 [4] 83 C4 04 89 85 [4] C6 45 ?? 27 3B C3 74 ?? 56 8B C8 E8 [4] EB ?? 33 C0 68 48 05 00 00 88 5D ?? 89 86 [4] E8 }
	condition:
		#pattern == 1
}

//294 CRxMgrPortal * mgr_portal;
rule CRxMgrNpc_mgr_portal
{
	meta:
		script = "$result = [@pattern + 0x3a]"
		script = "Type.am CRxMgrNpc,CRxMgrPortal*,mgr_portal,0,$result"
		script = "Type.mcomment CRxMgrNpc,mgr_portal,\"单线传送管理\""
	strings:
		$pattern = { 68 70 02 00 00 88 5D ?? 89 86 [4] E8 [4] 83 C4 04 89 85 [4] C6 45 ?? 2D 3B C3 74 ?? 56 8B C8 E8 [4] EB ?? 33 C0 68 44 02 00 00 88 5D ?? 89 86 [4] E8 }
	condition:
		#pattern == 1
}

//2ac CRxMgrRaise * mgr_raise;
rule CRxMgrNpc_mgr_raise
{
	meta:
		script = "$result = [@pattern + 0x3a]"
		script = "Type.am CRxMgrNpc,CRxMgrRaise*,mgr_raise,0,$result"
		script = "Type.mcomment CRxMgrNpc,mgr_raise,\"提真管理\""
	strings:
		$pattern = { 68 D4 02 00 00 88 5D ?? 89 86 [4] E8 [4] 83 C4 04 89 85 [4] C6 45 ?? 33 3B C3 74 ?? 56 8B C8 E8 [4] EB ?? 33 C0 68 [4] 88 5D ?? 89 86 [4] E8 }
	condition:
		#pattern == 1
}


//2c4 char w_sub;
rule CRxMgrNpc_w_sub
{
	meta:
		script = "$result = [@pattern + 0x0d]"
		script = "Type.am CRxMgrNpc,char,w_sub,0,$result"
		script = "Type.mcomment CRxMgrNpc,w_sub,\"子窗口打开标志\""
	strings:
		$pattern = { 6A 00 6A 00 8B CE E8 [4] C6 86 [4] 00 A1 [4] C7 05 [4] FF FF FF FF 8B 88 [4] 83 B9 [4] 04 75 ?? 6A FF 6A 04 6A 00 E8 }
	condition:
		#pattern == 1	
}

//2c5 char w_main;
rule CRxMgrNpc_w_main
{
	meta:
		script = "$result = [@pattern + 0x16]"
		script = "Type.am CRxMgrNpc,char,w_main,0,$result"
		script = "Type.mcomment CRxMgrNpc,w_main,\"主窗口打开标志\""
	strings:
		$pattern = { 6A 01 52 8B CE E8 [4] C7 05 [4] 01 00 00 00 C6 86 [4] 01 8B 8D [4] 8B 01 83 F8 31 74 ?? 83 F8 36 74 ?? 3D 9C 00 00 00 }
	condition:
		#pattern == 1	
}

//30C int w_btn[5];
rule CRxMgrNpc_w_btn
{
	meta:
		script = "$result = [@pattern + 0x29]"
		script = "Type.am CRxMgrNpc,int,w_btn,5,$result"
		script = "Type.mcomment CRxMgrNpc,w_btn,\"按钮功能号\""
	strings:
		$pattern = { 39 41 ?? 0F 85 [4] 38 86 [4] 0F 85 [4] 8B 4D ?? 83 F9 FF 0F 84 [4] 88 86 [4] 8D BE [4] 89 0D [4] 89 07 89 47 04 89 47 08 89 47 0C 53}
	condition:
		#pattern == 1	
}

//338 CRxWnd * dlg_npc;
//344 CRxButton * npc_bn_close;
rule CRxMgrNpc_dlg_npc
{
	meta:
		script = "$result = [@pattern + 0x22]"
		script = "Type.am CRxMgrNpc,CRxWnd*,dlg_npc,0,$result"
		script = "Type.mcomment CRxMgrNpc,dlg_npc,\"NPC窗口\""
		//script = "$result = [@pattern + 0x28]"
		//script = "Type.am CRxMgrNpc,CRxButton*,npc_bn_close,0,$result"
	strings:
		$pattern = { 6A 5A [3] CC 01 00 00 [3] 1A ?? 68 CC 01 00 00 6A 1A [2] E8 [8] 8B 8E [4] 89 86 }
	condition:
		#pattern == 1	
}

//2c8 CRxButton * npc_bn_events[5];
//324 CRxLabel * npc_lb_captions[5];
//rule CRxMgrNpc_npc_bn_events
//{
//	meta:
//		script = "$result = [@pattern1 + 0x12]"
//		script = "Type.am CRxMgrNpc,CRxButton*,npc_bn_events,5,$result"
//		script = "Type.mcomment CRxMgrNpc,npc_bn_events,\"NPC菜单按钮\""
//		
//		script = "$result += byte:[@pattern2 + 0x1b]"
//		script = "Type.am CRxMgrNpc,CRxLabel*,npc_lb_captions,5,$result"
//		script = "Type.mcomment CRxMgrNpc,npc_lb_captions,\"NPC菜单标签\""
//	strings:
//		$pattern1 = { 89 9D [4] C7 85 [4] E6 00 00 00 8D BE [4] 8D 95 [4] 52 68 [4] E8 [4] 68 F0 03 00 00 E8 }
//		$pattern2 = { 56 51 8B 8D [4] 52 6A 05 51 6A 1A [2] E8 [8] 89 47 ?? 8B 96 }
//	condition:
//		for all of them : (# == 1)
//}

rule CRxMgrNpc_end
{
	meta:
		script = "Type.print CRxMgrNpc,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}
