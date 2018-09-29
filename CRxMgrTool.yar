rule CRxMgrTool_start
{
	meta:
		script = "Type.as CRxMgrTool"
		script = "Type.aanc CRxMgrTool,CRxMgr"
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

//51c->5b4
//520->5b8
//524->5bc
//528->5c0
//528 CRxButton * toolbar_bn_maker;
rule CRxMgrTool_toolbar_bn_maker
{
	meta:
		script = "$result = [@pattern + 0x6]"
		script = "Type.am CRxMgrTool,CRxButton*,toolbar_bn_maker,0,$result"
		script = "Type.mcomment CRxMgrTool,dlg_toolbar,\"打开制造窗口\""
	strings:
		$pattern = { 6A FF 6A 40 89 86 [4] 8B 0D [4] 68 26 11 00 00 C6 45 ?? 02 }
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

//3B8 CRxButton * notify_bn_cancel;
rule CRxMgrTool_notify_bn_cancel
{
	meta:
		script = "$result = [@pattern + 0x29]"
		script = "Type.am CRxMgrTool,CRxButton*,notify_bn_cancel,0,$result"
		script = "Type.mcomment CRxMgrTool,notify_bn_cancel,\"关闭通知窗口\""
	strings:
		$pattern = { 6A 12 [3] B2 00 00 00 [3] 77 ?? 68 B2 00 00 00 6A 77 [2] E8 [9] 6A 78 [3] 02 89 86 }
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

//3F4 CRxButton * dead0_bn_relive_here;
rule CRxMgrTool_dead0_bn_relive_here
{
	meta:
		script = "$result = [@pattern + 0x2c]"
		script = "Type.am CRxMgrTool,CRxButton*,dead0_bn_relive_here,0,$result"
		script = "Type.mcomment CRxMgrTool,dead0_bn_relive_here,\"原地复活按钮\""
	strings:
		$pattern = { C6 45 ?? 37 [4] 6A 01 [2] 6A 73 68 03 01 00 00 6A 05 6A 3C 6A 14 [2] E8 [8] 8B 96 [4] 89 86 }
	condition:
		#pattern == 1
}

//424 CRxButton * dead0_bn_relive_back;
rule CRxMgrTool_dead0_bn_relive_back
{
	meta:
		script = "$result = [@pattern + 0x2a]"
		script = "Type.am CRxMgrTool,CRxButton*,dead0_bn_relive_back,0,$result"
		script = "Type.mcomment CRxMgrTool,dead0_bn_relive_back,\"回城复活按钮\""
	strings:
		$pattern = { 53 6A 63 [3] B2 00 00 00 [3] 77 ?? 68 B2 00 00 00 6A 77 [2] E8 [9] 6A 78 C6 45 ?? 02 89 86 }
	condition:
		#pattern == 1
}

//430 CRxButton * dead1_bn_relive_here;
rule CRxMgrTool_dead1_bn_relive_here
{
	meta:
		script = "$result = [@pattern + 0x29]"
		script = "Type.am CRxMgrTool,CRxButton*,dead1_bn_relive_here,0,$result"
		script = "Type.mcomment CRxMgrTool,dead1_bn_relive_here,\"原地复活按钮\""
	strings:
		$pattern = { 6A 32 [3] B2 00 00 00 [3] 55 ?? 68 B2 00 00 00 6A 55 [2] E8 [9] 6A 78 C6 45 ?? 02 89 86 }
	condition:
		#pattern == 1
}

//434 CRxButton * dead1_bn_relive_back;
rule CRxMgrTool_dead1_bn_relive_back
{
	meta:
		script = "$result = [@pattern + 0x2f]"
		script = "Type.am CRxMgrTool,CRxButton*,dead1_bn_relive_back,0,$result"
		script = "Type.mcomment CRxMgrTool,dead1_bn_relive_back,\"回城复活按钮\""
	strings:
		$pattern = { 6A 33 [3] B2 00 00 00 [3] 9C 00 00 00 ?? 68 B2 00 00 00 68 9C 00 00 00 [2] E8 [9] 6A 78 C6 45 ?? 02 89 86 }
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