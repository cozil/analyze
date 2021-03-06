rule CRxMgrTeam_start
{
	meta:
		script = "Type.as CRxMgrTeam"
		script = "Type.aanc CRxMgrTeam,CRxMgr"
		script = "Type.comment CRxMgrTeam, \"组队管理\""
		script = "Type.ad CRxMgrTeam,\"static const int msgbox_accept_id = 0x62;\""
		script = "Type.ad CRxMgrTeam,\"static const int msgbox_reject_id = 0x63;\""		
		
		script = "Type.ad CRxMgrTeam,\"inline void click_msgbox_accept() {{ click(msgbox_accept_id); }}\""
		script = "Type.ad CRxMgrTeam,\"inline void click_msgbox_reject() {{ click(msgbox_reject_id); }}\""
		
		script = "Type.ad CRxMgrTeam,\"inline bool req_activated() const {{ return (dlg_msgbox->visible != 0); }}\""
		script = "Type.ad CRxMgrTeam,\"inline bool req_inviting() const {{ return (req_activated() && (dlg_msgbox->flag == 0)); }}\""
		script = "Type.ad CRxMgrTeam,\"inline bool req_accepting() const {{ return (req_activated() && (dlg_msgbox->flag == 1)); }}\""
	condition:
		true
}

//228 CRxWnd * dlg_msgbox;
rule CRxMgrTeam_dlg_msgbox
{
	meta:
		script = "$result = [@pattern + 0x33]"
		script = "Type.am CRxMgrTeam,CRxWnd*,dlg_msgbox,0,$result"
	strings:
		$pattern = { 6A 61 [3] B2 00 00 00 [3] 77 ?? 68 B2 00 00 00 6A 77 [2] E8 [9] 6A 78 88 [2] 89 [5] E8 [4] 8B }
	condition:
		#pattern == 1
}

//270 short curr_playersid;
rule CRxMgrTeam_curr_playersid
{
	meta:
		script = "$result = [@pattern + 0x10]"
		script = "Type.am CRxMgrTeam,short,curr_playersid,0,$result"
		script = "Type.mcomment CRxMgrTeam,curr_playersid,\"当前交互的玩家sid\""
	strings:
		$pattern = { 66 [6] 89 [5] 66 [6] 88 [5] 88 [5] C7 [5] FF FF FF FF C6 [5] 01 }
	condition:
		#pattern >= 1
}

//280 int captain_sid;
rule CRxMgrTeam_captain_sid
{
	meta:
		script = "$result = [@pattern + 0x12]"
		script = "Type.am CRxMgrTeam,int,captain_sid,0,$result"
		script = "Type.mcomment CRxMgrTeam,captain_sid,\"队长sid\""
	strings:
		$pattern = { 66 [3] 01 0F [5] A1 [4] 39 [8] 9C 0C 00 00 }
	condition:
		#pattern == 1
}

//294 int selected_sid;
rule CRxMgrTeam_selected_sid
{
	meta:
		script = "$result = [@pattern + 0x20]"
		script = "Type.am CRxMgrTeam,int,selected_sid,0,$result"
		script = "Type.mcomment CRxMgrTeam,selected_sid,\"点击队员的下拉菜单，值会变为队友的sid\""
	strings:
		$pattern = { 28 00 00 00 ?? 01 00 00 00 66 89 [5] 66 89 [5] 8B [5] 0F B7 [7] 0C 66 89 [6] 04 00 00 00 }
	condition:
		#pattern == 1
}

//298 uint16_t team_level;
rule CRxMgrTeam_team_level
{
	meta:
		script = "$result = [@pattern + 0x1c]"
		script = "Type.am CRxMgrTeam,uint16_t,team_level,0,$result"
		script = "Type.mcomment CRxMgrTeam,team_level,\"队伍等级\""
	strings:
		$pattern = { 55 8b ec [8] 09 [6] 07 [6] 66 [18] ff }
	condition:
		#pattern == 1
}

//2c8 uint32_t fb_level;
rule CRxMgrTeam_fb_level
{
	meta:
		script = "$result = [@pattern + 0x2]"
		script = "Type.am CRxMgrTeam,uint32_t,fb_level,0,$result"
		script = "Type.mcomment CRxMgrTeam,fb_level,\"副本难度\""
	strings:
		$pattern = { 89 [10] 83 [5] 00 [19] E8 [6] 03 [13] 68 E7 0D 00 00 }
	condition:
		#pattern == 1
}

rule CRxMgrTeam_end
{
	meta:
		script = "Type.print CRxMgrTeam,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}