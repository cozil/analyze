
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
		
		script = "Type.ad CRxMgrNpc,\"int find_npc_flag(int flag) const;\""
		script = "Type.ad CRxMgrNpc,\"bool is_npc_window_active() const;\""
	condition:
		true
}

//228 CRxMgrShop * mgr_shop
rule CRxMgrNpc_mgr_shop
{
	meta:
		script = "$result = [@pattern + 0x4b]"
		script = "Type.am CRxMgrNpc,CRxMgrShop*,mgr_shop,0,$result"
		script = "Type.mcomment CRxMgrNpc,mgr_shop,\"NPC商店管理\""
	strings:
		//offset:0x4b
		$pattern = { 83 C1 03 69 C9 [4] 81 C1 [60] 50 51 8B 8A [4] E8 [4] 83 C6 04 4F }
		//offset:0x34
		//$pattern = { 68 58 02 00 00 89 79 ?? E8 [4] 83 C4 04 89 85 [4] C6 45 ?? 13 3B C3 74 ?? 56 8B C8 E8 [4] EB ?? 33 C0 68 48 02 00 00 88 5D ?? 89 86 [4] E8 }
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
		$pattern = { 68 [4] 88 [2] 89 [5] e8 [16] 14 [7] e8 [8] 68 [4] 88 [2] 89 [5] e8 [13] c6 [2] 15 }
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
		$pattern = { 68 [4] 88 [2] 89 [5] e8 [16] 15 [7] e8 [8] 68 [4] 88 [2] 89 [5] e8 [13] c6 [2] 16 }
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
		$pattern = { 33 C0 68 [4] 88 [2] 89 [5] E8 [7] 89 [5] C6 [2] 17 [7] E8 [8] 68 [4] 88 [2] 89 [5] E8 }
	condition:
		#pattern == 1	
}

//27C CRxMgrPk * mgr_pk;
rule CRxMgrNpc_mgr_pk
{
	meta:
		script = "$result = [@pattern + 0x3a]"
		script = "Type.am CRxMgrNpc,CRxMgrPk*,mgr_pk,0,$result"
		script = "Type.mcomment CRxMgrNpc,mgr_pk,\"PK管理\""
	strings:
		$pattern = { 68 [4] 88 [2] 89 [5] E8 [7] 89 [5] C6 [2] 27 [7] E8 [8] 68 [4] 88 [2] 89 [5] E8 }
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
		$pattern = { 68 [4] 88 [2] 89 [5] E8 [7] 89 [5] C6 [2] 2D [7] E8 [8] 68 [4] 88 [2] 89 [5] E8 }
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
		$pattern = { 68 [4] 88 [2] 89 [5] E8 [7] 89 [5] C6 [2] 33 [7] E8 [8] 68 [4] 88 [2] 89 [5] E8 }
	condition:
		#pattern == 1
}


//2c4 uint8_t w_sub;
rule CRxMgrNpc_w_sub
{
	meta:
		script = "$result = [@pattern + 0x0d]"
		script = "Type.am CRxMgrNpc,uint8_t,w_sub,0,$result"
		script = "Type.mcomment CRxMgrNpc,w_sub,\"子窗口打开标志\""
	strings:
		$pattern = { 6A 00 6A 00 8B CE E8 [4] C6 86 [4] 00 A1 [4] C7 05 [4] FF FF FF FF 8B 88 [4] 83 B9 [4] 04 75 ?? 6A FF 6A 04 6A 00 E8 }
	condition:
		#pattern == 1	
}

//2c5 uint8_t w_main;
rule CRxMgrNpc_w_main
{
	meta:
		script = "$result = [@pattern + 0x16]"
		script = "Type.am CRxMgrNpc,uint8_t,w_main,0,$result"
		script = "Type.mcomment CRxMgrNpc,w_main,\"主窗口打开标志\""
	strings:
		$pattern = { 6A 01 52 8B CE E8 [4] C7 05 [4] 01 00 00 00 C6 86 [4] 01 8B 8D [4] 8B 01 83 F8 31 74 ?? 83 F8 36 74 ?? 3D 9C 00 00 00 }
	condition:
		#pattern == 1	
}

//30C uint32_t w_btn[5];
rule CRxMgrNpc_w_btn
{
	meta:
		script = "$result = [@pattern + 0x29]"
		script = "Type.am CRxMgrNpc,uint32_t,w_btn,5,$result"
		script = "Type.mcomment CRxMgrNpc,w_btn,\"按钮功能号\""
	strings:
		$pattern = { 39 41 ?? 0F 85 [4] 38 86 [4] 0F 85 [4] 8B 4D ?? 83 F9 FF 0F 84 [4] 88 86 [4] 8D BE [4] 89 0D [4] 89 07 89 47 04 89 47 08 89 47 0C 53}
	condition:
		#pattern == 1	
}

//338 CRxWnd * dlg_npc;
rule CRxMgrNpc_dlg_npc
{
	meta:
		script = "$result = [@pattern + 0x22]"
		script = "Type.am CRxMgrNpc,CRxWnd*,dlg_npc,0,$result"
		script = "Type.mcomment CRxMgrNpc,dlg_npc,\"NPC窗口\""
	strings:
		$pattern = { 6A 5A [3] CC 01 00 00 [3] 1A ?? 68 CC 01 00 00 6A 1A [2] E8 [8] 8B 8E [4] 89 86 }
	condition:
		#pattern == 1	
}

rule CRxMgrNpc_end
{
	meta:
		script = "Type.print CRxMgrNpc,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}
