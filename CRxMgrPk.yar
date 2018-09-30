
//
//CRxMgrPk部分成员偏移分析
//

rule CRxMgrPk_start
{
	meta:
		script = "Type.as CRxMgrPk"
		script = "Type.aanc CRxMgrPk,CRxMgr"
		script = "Type.comment CRxMgrPk,\"PK管理\""
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
		$pattern = { 68 70 03 00 00 E8 [4] 83 C4 04 89 85 [4] C6 45 ?? 0D 3B C3 74 ?? 56 8B C8 E8 [4] EB ?? 33 C0 89 86 }
	condition:
		#pattern == 1
}


//22C short pk_state;
//240 CRxWndPkQuery * dlg_pkquery;
rule CRxMgrPk_dlg_pkquery
{
	meta:
		script = "$result = [@pattern + 0x2c]"
		script = "Type.am CRxMgrPk,short,pk_state,0,$result"
		script = "Type.mcomment CRxMgrPk,pk_state,\"状态 0:无 1:收到报名窗口 2:收到进战提示窗口.\n仅在dlg_pkquery显示时有效，窗口关闭时为0\""
		script = "$result = [@pattern + 0x18]"
		script = "Type.am CRxMgrPk,CRxWnd*,dlg_pkquery"
		script = "Type.mcomment CRxMgrPk,dlg_pkquery,\"进风云势力战提示窗口\""
	strings:
		$pattern = { 0F B6 80 [4] 53 FF 24 85 [4] 8A 5D ?? 0F B6 CB 51 8B 8E [4] E8 [4] 0F B6 D3 F7 DA 1B D2 23 D7 89 96 [4] 84 DB 0F 84 [4] FF 15 }
	condition:
		#pattern == 1		
}

//244 CRxButton * pkquery_bn_accept;
rule CRxMgrPk_pkquery_bn_accept
{
	meta:
		script = "$result = [@pattern + 0x35]"
		script = "Type.am CRxMgrPk,CRxButton*,pkquery_bn_accept,0,$result"
	strings:
		$pattern = { D9 05 [4] 8B 96 [4] D9 9D [4] D9 05 [4] 8B 8D [4] 53 D9 9D [4] 53 6A 03 68 [4] 68 [4] 53 89 86 }
	condition:
		#pattern == 1
}

//248 CRxButton * pkquery_bn_reject;
rule CRxMgrPk_pkquery_bn_reject
{
	meta:
		script = "$result = [@pattern + 0x73]"
		script = "Type.am CRxMgrPk,CRxButton*,pkquery_bn_reject,0,$result"
	strings:
		$pattern = { 6A 03 [59] 6A 01 D9 9D [4] D9 05 [4] 68 00 00 00 C8 6A FF D9 9D [4] D9 05 [4] 6A 05 68 [4] D9 9D [4] 8B 95 [4] 89 86 }
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

//264 CRxButton * zdInvite_bn_accept;
//268 CRxButton * zdInvite_bn_reject;
rule CRxMgrPk_zdInvite_btns
{
	meta:
		script = "$result = [@pattern + 0xf]"
		script = "Type.am CRxMgrPk,CRxButton*,zdInvite_bn_accept,0,$result"
		script = "$result = [@pattern + 0x5c]"
		script = "Type.am CRxMgrPk,CRxButton*,zdInvite_bn_reject,0,$result"
	strings:
		$pattern = { 6A 1C [11] 89 86 [4] 8B 85 [4] 50 51 52 56 E8 [4] D9 05 [4] 83 C4 50 D9 9D [4] D9 05 [4] 6A 01 68 00 00 00 C8 D9 9D [4] D9 05 [4] 6A FF D9 9D [4] 6A 05 D9 05 [4] 89 86 }
	condition:
		#pattern == 1
}


//270 CRxWnd * dlg_zdconfirm
rule CRxMgrPk_dlg_zdconfirm
{
	meta:
		script = "$result = [@pattern + 0x1f]"
		script = "Type.am CRxMgrPk,CRxWnd*,dlg_zdconfirm,0,$result"
		script = "Type.mcomment CRxMgrPk,dlg_zdInvite,\"真斗烈战参战窗口\""
	strings:
		$pattern = { 53 6A 14 68 [4] 68 [4] 53 50 51 52 56 E8 [4] D9 05 [4] 8B 96 }
	condition:
		#pattern == 1
}

//274 CRxButton * zdconfirm_bn_accept;
//278 CRxButton * zdconfirm_bn_reject;
rule CRxMgrPk_zdconfirm_btns
{
	meta:
		script = "$result = [@pattern + 0xf]"
		script = "Type.am CRxMgrPk,CRxButton*,zdconfirm_bn_accept,0,$result"
		script = "$result = [@pattern + 0x5c]"
		script = "Type.am CRxMgrPk,CRxButton*,zdconfirm_bn_reject,0,$result"
	strings:
		$pattern = { 6A 15 68 [4] 68 [4] 53 89 86 [4] 8B 85 [4] 50 51 52 56 E8 [4] D9 05 [4] 83 C4 50 D9 9D [4] D9 05 [4] 6A 01 68 00 00 00 C8 D9 9D [4] D9 05 [4] 6A FF D9 9D [4] 6A 05 D9 05 [4] 89 86 }
	condition:
		#pattern == 1
}

//5B0 CRxWnd * dlg_relive
//5B4 CRxButton * relive_bn_src;
//5B8 CRxButton * relive_bn_dst;
rule CRxMgrPk_dlg_relive
{
	meta:
		script = "$result = [@pattern + 0x2]"
		script = "Type.am CRxMgrPk,CRxWnd*,dlg_relive,0,$result"
		script = "Type.mcomment CRxMgrPk,dlg_relive,\"势力战死亡复活窗口\""
		script = "$result = [@pattern + 0x30]"
		script = "Type.am CRxMgrPk,CRxButton*,relive_bn_dst,0,$result"
		script = "Type.mcomment CRxMgrPk,relive_bn_dst,\"对立地区复活\""
		script = "$result = [@pattern + 0x5c]"
		script = "Type.am CRxMgrPk,CRxButton*,relive_bn_src,0,$result"
		script = "Type.mcomment CRxMgrPk,relive_bn_src,\"据点地区复活\""
	strings:
		$pattern = { 8B 8E [4] D9 9D [4] D9 05 [4] 53 53 D9 9D [4] 8B 95 [4] 6A 0A 68 [4] 68 [4] 53 52 89 86 [4] 8B 85 [4] 50 51 56 E8 [4] 8B 95 [4] 83 C4 50 6A 01 6A 01 53 53 53 68 [4] 57 52 56 89 86 }
	condition:
		#pattern == 1
}


//5bc int battle_start;
rule CRxMgrPk_battle_start
{
	meta:
		script = "$result = [@pattern + 0x30]"
		script = "Type.am CRxMgrPk,int,battle_start,0,$result"
		script = "Type.mcomment CRxMgrPk,battle_start,\"1:已开战 0:未开战\""
	strings:
		$pattern = { 83 FA 62 77 ?? 6A 01 6A 01 8B CE E8 [4] E9 [4] 3D 41 9C 00 00 0F 85 [4] 6A 01 8B CE E8 [4] E9 [4] 39 BE [4] 74 ?? E8 }
	condition:
		#pattern == 1		
}

//8C8 CRxButton * bn_enterfight;
rule CRxMgrPk_bn_enterfight
{
	meta:
		script = "$result = [@pattern + 0x28]"
		script = "Type.am CRxMgrPk,CRxButton*,bn_enterfight,0,$result"
		script = "Type.mcomment CRxMgrPk,bn_enterfight,\"进入势力战按钮\""
	strings:
		$pattern = { 53 53 6A 08 68 [4] 68 [4] 68 [4] 52 50 51 56 E8 [4] 83 C4 28 68 [4] 8B C8 89 86 }
	condition:
		#pattern == 1
}

//8D0 CRxButton * bn_enterbattle;
rule CRxMgrPk_bn_enterbattle
{
	meta:
		script = "$result = [@pattern + 0x28]"
		script = "Type.am CRxMgrPk,CRxButton*,bn_enterbattle,0,$result"
		script = "Type.mcomment CRxMgrPk,bn_enterbattle,\"进入风云大战按钮\""
	strings:
		$pattern = { 53 53 6A 09 68 [4] 68 [4] 68 [4] 50 51 52 56 E8 [4] 83 C4 28 68 [4] 8B C8 89 86 }
	condition:
		#pattern == 1
}


//8D4 CRxWnd * dlg_goback1
//8D8 CRxButton * bn_goback1;
rule CRxMgrPk_dlg_goback1
{
	meta:
		script = "$result = [@pattern + 0x15]"
		script = "Type.am CRxMgrPk,CRxWnd*,dlg_goback1,0,$result"
		script = "Type.mcomment CRxMgrPk,dlg_goback1,\"回到村庄窗口，显示时表示势力战结束，有地图时显示这个\""
		script = "$result = [@pattern + 0x20]"
		script = "Type.am CRxMgrPk,CRxButton*,bn_goback1,0,$result"
	strings:
		$pattern = { 53 53 6A 0F 68 [4] 68 [4] 53 51 52 50 56 89 86 [4] E8 [4] 89 86 [4] 8B 86 }
	condition:
		#pattern == 1
}

//8DC CRxWnd * dlg_goback2
//8E0 CRxButton * bn_goback2;
rule CRxMgrPk_dlg_goback2
{
	meta:
		script = "$result = [@pattern + 0x14]"
		script = "Type.am CRxMgrPk,CRxWnd*,dlg_goback2,0,$result"
		script = "Type.mcomment CRxMgrPk,dlg_goback2,\"关掉地图时显示这个\""
		script = "$result = [@pattern + 0x1f]"
		script = "Type.am CRxMgrPk,CRxButton*,bn_goback2,0,$result"
	strings:
		$pattern = { 53 6A 10 68 [4] 68 [4] 53 51 52 50 56 89 86 [4] E8 [4] 89 86 }
	condition:
		#pattern == 1
}


//A80 char score_flag;
rule CRxMgrPk_score_flag
{
	meta:
		script = "$result = [@pattern + 0x1a]"
		script = "Type.am CRxMgrPk,char,score_flag,0,$result"
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