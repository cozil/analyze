rule CRxMgrTool_start
{
	meta:
		script = "Type.as CRxMgrTool"
		script = "Type.aanc CRxMgrTool,CRxMgr"
		script = "Type.ad CRxMgrTool,\"inline void click_toolbar_maker() {{ click(0xbb9); }}\""
		script = "Type.ad CRxMgrTool,\"inline void click_notify_cancel() {{ click(0x12); }}\""
		script = "Type.ad CRxMgrTool,\"inline void click_dead0_backtown() {{ click(0x63); }}\""
		script = "Type.ad CRxMgrTool,\"inline void click_dead1_here() {{ click(0x32); }}\""
		script = "Type.ad CRxMgrTool,\"inline void click_dead1_backtown() {{ click(0x33); }}\""
	condition:
		true
}

//244 CRxWnd * dlg_toolbar;
rule CRxMgrTool_dlg_toolbar
{
	meta:
		script = "$result = [@pattern + 0x1e]"
		script = "Type.am CRxMgrTool,CRxWnd*,dlg_toolbar,0,$result"
		script = "Type.mcomment CRxMgrTool,dlg_toolbar,\"系统工具栏\""
	strings:
		$pattern = { 8B 15 [4] 53 6A 01 56 68 [4] 51 52 8B C8 E8 [4] EB ?? 33 C0 89 86 [4] C6 80 [4] 01 }
	condition:
		#pattern == 1
}

//384 CRxImage * img_docbar;
rule CRxMgrTool_img_docbar
{
	meta:
		script = "$result = [@pattern + 0x22]"
		script = "Type.am CRxMgrTool,CRxImage*,img_docbar,0,$result"
		script = "Type.mcomment CRxMgrTool,img_docbar,\"医生黄条绘制管理\""
	strings:
		$pattern = { 53 53 56 68 [4] 53 51 52 6A 26 6A 36 [2] E8 [4] EB ?? 33 C0 8B 8E [4] 89 86 }
	condition:
		#pattern == 1
}

//3B0 CRxWnd * dlg_notify;
rule CRxMgrTool_dlg_notify
{
	meta:
		script = "$result = [@pattern + 0x2e]"
		script = "Type.am CRxMgrTool,CRxWnd*,dlg_notify,0,$result"
		script = "Type.mcomment CRxMgrTool,dlg_notify,\"通知消息窗口。显示时不影响挂机\""
	strings:
		$pattern = { C6 45 ?? 47 [10] 6A 01 6A 01 56 68 [4] 51 57 8B C8 E8 [4] EB ?? 33 C0 [3] C6 45 ?? 02 89 86 }
	condition:
		#pattern == 1
}

//3E8 CRxWnd * dlg_blood;
rule CRxMgrTool_dlg_blood
{
	meta:
		script = "$result = [@pattern + 0xa]"
		script = "Type.am CRxMgrTool,CRxWnd*,dlg_blood,0,$result"
		script = "Type.mcomment CRxMgrTool,dlg_blood,\"血条窗口\""
	strings:
		$pattern = { 6A 01 [5] 02 89 86 [4] E8 [4] 8B 86 [4] C6 80 [4] 01 8B 8E }
	condition:
		#pattern == 1
}

//3EC CRxWnd * dlg_dead0;
rule CRxMgrTool_dlg_dead0
{
	meta:
		script = "$result = [@pattern + 0x29]"
		script = "Type.am CRxMgrTool,CRxWnd*,dlg_dead0,0,$result"
		script = "Type.mcomment CRxMgrTool,dlg_dead0,\"默认死亡复活窗口(仅回城复活)\""
	strings:
		$pattern = { C6 45 ?? 36 [4] 6A 01 6A 01 56 68 [4] 6A 5F 57 8B C8 E8 [11] C6 45 ?? 02 89 86 }
	condition:
		#pattern == 1
}

//3F0 CRxWnd * dlg_dead1;
rule CRxMgrTool_dlg_dead1
{
	meta:
		script = "$result = [@pattern + 0x29]"
		script = "Type.am CRxMgrTool,CRxWnd*,dlg_dead1,0,$result"
		script = "Type.mcomment CRxMgrTool,dlg_dead1,\"至尊符死亡复活窗口\""
	strings:
		$pattern = { C6 45 ?? 3B [4] 6A 01 6A 01 56 68 [4] 6A 5F [2] C8 E8 [11] C6 45 ?? 02 89 86 }
	condition:
		#pattern == 1
}

//510 CRxWnd * dlg_keybar;
rule CRxMgrTool_dlg_keybar
{
	meta:
		script = "$result = [@pattern + 0x27]"
		script = "Type.am CRxMgrTool,CRxWnd*,dlg_keybar,0,$result"
		script = "Type.mcomment CRxMgrTool,dlg_keybar,\"快捷键工具栏\""
	strings:
		$pattern = { 8D 0C 49 51 8B 0D [4] 52 8B 15 [4] 51 52 8B C8 E8 [9] 8B C8 [4] 89 86 }
	condition:
		#pattern == 1
}

rule CRxMgrTool_end
{
	meta:
		script = "Type.print CRxMgrTool,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}