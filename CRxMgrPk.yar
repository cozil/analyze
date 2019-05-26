
//
//CRxMgrPk部分成员偏移分析
//

rule CRxMgrPk_start
{
	meta:
		script = "Type.as CRxMgrPk"
		script = "Type.aanc CRxMgrPk,CRxMgr"
		script = "Type.comment CRxMgrPk,\"PK管理\""
		script = "Type.ad CRxMgrPk,\"static const int pkquery_accept_id = 0x2;\""
		script = "Type.ad CRxMgrPk,\"static const int pkquery_reject_id = 0x3;\""
		script = "Type.ad CRxMgrPk,\"static const int zdinvite_accept_id = 0x11;\""
		script = "Type.ad CRxMgrPk,\"static const int zdinvite_reject_id = 0x1c;\""
		script = "Type.ad CRxMgrPk,\"static const int zdenter_accept_id = 0x14;\""
		script = "Type.ad CRxMgrPk,\"static const int zdenter_reject_id = 0x15;\""
		script = "Type.ad CRxMgrPk,\"static const int relive_dst_id = 0xb; //对立复活\""
		script = "Type.ad CRxMgrPk,\"static const int relive_src_id = 0xa; //据点复活\""
		script = "Type.ad CRxMgrPk,\"static const int enter_fight_id = 0x8; //进入势力战\""
		script = "Type.ad CRxMgrPk,\"static const int enter_battle_id = 0x9; //进入风云大战\""
		script = "Type.ad CRxMgrPk,\"static const int goback1_id = 0xf; //返回村庄1\""
		script = "Type.ad CRxMgrPk,\"static const int goback2_id = 0x10; //返回村庄2\""
		
		script = "Type.ad CRxMgrPk,\"inline bool battle_over() const {{ return (dlg_goback1->visible || dlg_goback2->visible); }}\""
		script = "Type.ad CRxMgrPk,\"inline bool battle_processing() const {{ return (battle_start == 1); }}\""
	condition:
		true
}

//228 CRxMgrFypk * mgr_fypk
rule CRxMgrPk_mgr_fypk
{
	meta:
		script = "$result = [@pattern + 0x29]"
		script = "Type.am CRxMgrPk,CRxMgrFypk*,mgr_fypk,0,$result"
		script = "Type.mcomment CRxMgrPk,mgr_fypk,\"风云大战管理\""
	strings:
		$pattern = { 68 [4] E8 [7] 89 [5] C6 [2] 0D [7] E8 [8] 89 }
	condition:
		#pattern == 1
}


//22C uint16_t pk_state;
//240 CRxWndPkQuery * dlg_pkquery;
rule CRxMgrPk_dlg_pkquery
{
	meta:
		script = "$result = [@pattern + 0x2c]"
		script = "Type.am CRxMgrPk,uint16_t,pk_state,0,$result"
		script = "Type.mcomment CRxMgrPk,pk_state,\"状态 0:无 1:收到报名窗口 2:收到进战提示窗口.\n仅在dlg_pkquery显示时有效，窗口关闭时为0\""
		script = "$result = [@pattern + 0x18]"
		script = "Type.am CRxMgrPk,CRxWnd*,dlg_pkquery,0,$result"
		script = "Type.mcomment CRxMgrPk,dlg_pkquery,\"进风云势力战提示窗口\""
	strings:
		$pattern = { 0F B6 80 [4] 53 FF 24 85 [4] 8A 5D ?? 0F B6 CB 51 8B 8E [4] E8 [4] 0F B6 D3 F7 DA 1B D2 23 D7 89 96 [4] 84 DB 0F 84 [4] FF 15 }
	condition:
		#pattern == 1		
}

//260 CRxWnd * dlg_zdInvite
rule CRxMgrPk_dlg_zdInvite
{
	meta:
		script = "$result = [@pattern + 0x6]"
		script = "Type.am CRxMgrPk,CRxWnd*,dlg_zdInvite,0,$result"
		script = "Type.mcomment CRxMgrPk,dlg_zdInvite,\"真斗烈战邀请窗口\""
	strings:
		$pattern = { 6A 01 8B C8 89 86 [4] E8 [4] D9 05 [4] 8B 96 [4] D9 9D [4] D9 05 [4] 8B 8D [4] 53 D9 9D [4] 8B 85 [4] 53 6A 11 }
	condition:
		#pattern == 1
}

//270 CRxWnd * dlg_zdconfirm
rule CRxMgrPk_dlg_zdconfirm
{
	meta:
		script = "$result = [@pattern + 0x1f]"
		script = "Type.am CRxMgrPk,CRxWnd*,dlg_zdconfirm,0,$result"
		script = "Type.mcomment CRxMgrPk,dlg_zdconfirm,\"真斗烈战参战窗口\""
	strings:
		$pattern = { 53 6A 14 68 [4] 68 [4] 53 50 51 52 56 E8 [4] D9 05 [4] 8B 96 }
	condition:
		#pattern == 1
}

//5B0 CRxWnd * dlg_relive
rule CRxMgrPk_dlg_relive
{
	meta:
		script = "$result = [@pattern + 0x41]"
		script = "Type.am CRxMgrPk,CRxWnd*,dlg_relive,0,$result"
		script = "Type.mcomment CRxMgrPk,dlg_relive,\"势力战死亡复活窗口\""
	strings:
		$pattern = { C6 [2] 06 [22] 6A 01 6A 01 [3] 68 [7] C6 [2] 04 89 [5] E8 [4] 83 C4 24 6A 01 [2] 89 }
	condition:
		#pattern == 1
}

//5bc uint32_t battle_start;
rule CRxMgrPk_battle_start
{
	meta:
		script = "$result = [@pattern + 0x30]"
		script = "Type.am CRxMgrPk,uint32_t,battle_start,0,$result"
		script = "Type.mcomment CRxMgrPk,battle_start,\"1:已开战 0:未开战\""
	strings:
		$pattern = { 83 FA 62 77 ?? 6A 01 6A 01 8B CE E8 [4] E9 [4] 3D 41 9C 00 00 0F 85 [4] 6A 01 8B CE E8 [4] E9 [4] 39 BE [4] 74 ?? E8 }
	condition:
		#pattern == 1		
}

//8D4 CRxWnd * dlg_goback1
rule CRxMgrPk_dlg_goback1
{
	meta:
		script = "$result = [@pattern + 0x15]"
		script = "Type.am CRxMgrPk,CRxWnd*,dlg_goback1,0,$result"
		script = "Type.mcomment CRxMgrPk,dlg_goback1,\"回到村庄窗口，显示时表示势力战结束，有地图时显示这个\""
	strings:
		$pattern = { 53 53 6A 0F 68 [4] 68 [4] 53 51 52 50 56 89 86 [4] E8 [4] 89 86 [4] 8B 86 }
	condition:
		#pattern == 1
}

//8DC CRxWnd * dlg_goback2
rule CRxMgrPk_dlg_goback2
{
	meta:
		script = "$result = [@pattern + 0x14]"
		script = "Type.am CRxMgrPk,CRxWnd*,dlg_goback2,0,$result"
		script = "Type.mcomment CRxMgrPk,dlg_goback2,\"关掉地图时显示这个\""
	strings:
		$pattern = { 53 6A 10 68 [4] 68 [4] 53 51 52 50 56 89 86 [4] E8 [4] 89 86 }
	condition:
		#pattern == 1
}

//A80 uint8_t score_flag;
rule CRxMgrPk_score_flag
{
	meta:
		script = "$result = [@pattern + 0x1a]"
		script = "Type.am CRxMgrPk,uint8_t,score_flag,0,$result"
		script = "Type.mcomment CRxMgrPk,score_flag,\"置1会定时发送请求包获取势力战排名得分数据\""
	strings:
		$pattern = { C6 86 [4] 00 C7 05 [4] 00 00 00 00 8B CE E8 [4] 80 BE [4] 00 74 ?? FF D3 2B 86 [4] 3D 88 13 00 00 }
	condition:
		#pattern == 1
}

rule CRxMgrPk_end
{
	meta:
		script = "Type.print CRxMgrPk,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}